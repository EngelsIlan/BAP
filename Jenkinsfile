pipeline {
    agent any

    tools {
        maven 'Maven' 
    }

    stages {
        stage('Checkout') {
            steps {
                sh 'cp -r /home/poc-devsecops/. .'
            }
        }

        stage('Maven Build') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Generate SBOM') {
            steps {
                sh '''
                    # Syft installeren
                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .

                    # SBOM genereren vanuit de volledige workspace (pom.xml + target/)
                    ./syft scan dir:. -o cyclonedx-json > sbom.cdx.json

                    # SBOM preview
                    echo "=== SBOM Preview ==="
                    cat sbom.cdx.json | jq '.components | length'
                    cat sbom.cdx.json | jq '.components[0:3] | .[] | {name, version}'
                '''
            }
        }

        stage('Validate & Archive') {
            steps {
                sh '''
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
                '''
                archiveArtifacts artifacts: 'sbom.cdx.json,target/*.jar', fingerprint: true
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}