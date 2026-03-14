pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Maven Build') {
            steps {
                sh '''
                    mvn clean package -DskipTests
                '''
            }
        }
        
        stage('Generate SBOM') {
            steps {
                sh '''
                    # Syft installeren (Linux/Mac)
                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .
                    
                    # SBOM genereren voor JAR + dependencies
                    ./syft packages:maven target/*.jar -o cyclonedx-json > sbom.cdx.json
                    
                    # SBOM preview
                    echo "=== SBOM Preview ==="
                    cat sbom.cdx.json | jq '.components | length' 
                    cat sbom.cdx.json | jq '.components[0:3] | .[] | {name, version}'
                '''
            }
        }
        
        stage('Validate & Archive') {
            steps {
                // Simpele validatie
                sh '''
                    # Controleer of SBOM geldig JSON is
                    cat sbom.cdx.json | jq empty
                    
                    # Controleer component count
                    COMPONENT_COUNT=$(cat sbom.cdx.json | jq '.components | length')
                    echo "Generated SBOM with $COMPONENT_COUNT components"
                    
                    if [ $COMPONENT_COUNT -eq 0 ]; then
                        error "No components found in SBOM!"
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