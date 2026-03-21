pipeline {
    agent any

    tools {
        maven 'Maven' 
    }

    stages {
        stage('Checkout') {
            steps {
                git url: 'https://github.com/spring-projects/spring-petclinic.git',
                    branch: 'main'
                sh 'ls -a'

            }
        }

        stage('Maven Build') {
            steps {
                sh '''
                    echo "STARTING MAVEN BUILD"
                    mvn clean package -DskipTests -q
                    echo "BUILD SUCCESS"
                '''
            }
        }

        // Deel 1: SBOM genereren met Syft, validatie & archiveren
        stage('Generate SBOM') {
            steps {
                sh '''
                    echo "GENERATING SBOM WITH SYFT"

                    # jq installeren voor JSON parsing
                    apt-get update -q
                    apt-get install -y jq
                    
                    # Syft installeren
                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .

                    # SBOM genereren vanuit de volledige workspace (pom.xml + target/)
                    ./syft scan dir:. -o cyclonedx-json > sbom.cdx.json

                    # SBOM preview
                    echo "=== SBOM Preview ==="
                    cat sbom.cdx.json | jq '.components | length'
                    cat sbom.cdx.json | jq '.components[0:3] | .[] | {name, version}'
                
                    echo "SBOM GENERATION COMPLETE"
                '''
            }
        }

        stage('Validate & Archive') {
            steps {
                sh '''
                    echo "VALIDATING SBOM"

                    # Controleer of SBOM geldig JSON is
                    cat sbom.cdx.json | jq empty

                    # Controleer component count
                    COMPONENT_COUNT=$(cat sbom.cdx.json | jq '.components | length')
                    echo "Generated SBOM with $COMPONENT_COUNT components"

                    # Groovy error() werkt niet in sh-blok, gebruik exit 1
                    if [ "$COMPONENT_COUNT" -eq 0 ]; then
                        echo "ERROR: No components found in SBOM!"
                        exit 1
                    fi

                    echo "SBOM VALIDATION SUCCESS"
                '''
                archiveArtifacts artifacts: 'sbom.cdx.json,target/*.jar', fingerprint: true
            }
        }

        // Deel 2: Dependency-check scan, HTML rapport genereren & fail bij HIGH/CRITICAL (>=7.0 CVSS)
        stage('Dependency Check scan') {
            steps {
                withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_API_KEY')]) {
                    sh '''
                        echo "STARTING OWASP DEPENDENCY-CHECK SCAN"

                        # Download Dependency-Check CLI
                        curl -L https://github.com/jeremylong/DependencyCheck/releases/download/v9.2.0/dependency-check-9.2.0-release.zip -o dependency-check.zip
                        unzip -q dependency-check.zip


                        # Scan de target/ directory waar de jar staat
                        ./dependency-check/bin/dependency-check.sh \
                            --project "spring-petclinic" \
                            --scan ./target/*.jar \
                            --format HTML \
                            --format JSON \
                            --out ./dependency-check-report \
                            --noupdate \
                            --failOnCVSS 7


                        echo "DEPENDENCY-CHECK SCAN COMPLETE"
                    '''
                }
            }
        }

        stage('Publish Report') {
            steps {
                publishHTML(target: [
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'dependency-check-report',
                    reportFiles: 'dependency-check-report.html',
                    reportName: 'OWASP Dependency-Check Report'
                ])
                archiveArtifacts artifacts: 'dependency-check-report/**', fingerprint: true
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}