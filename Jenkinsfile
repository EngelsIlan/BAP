pipeline {
    agent any

    environment {
        IMAGE_NAME = "spring-petclinic:${BUILD_NUMBER}"
    }

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

        stage('Build Container Image') {
            steps {
                sh '''
                    git clone https://github.com/EngelsIlan/BAP.git
                    echo "BUILDING DOCKER IMAGE"
                    docker build -f BAP/Docker/Dockerfile -t spring-petclinic:${BUILD_NUMBER} .
                    docker images | grep spring-petclinic
                '''
            }
        }

        stage('Parallel Security Checks') {
            parallel {

                stage('SBOM Flow') {
                    stages {
                        stage('Generate SBOM') {
                            steps {
                                sh '''
                                    echo "GENERATING SBOM WITH SYFT"

                                    apt-get update -q
                                    apt-get install -y jq python3

                                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b .

                                    ./syft scan dir:. -o cyclonedx-json > sbom.cdx.json

                                    echo "=== SBOM Preview ==="
                                    cat sbom.cdx.json | jq '.components | length'
                                    cat sbom.cdx.json | jq '.components[0:3] | .[] | {name, version}'
                                '''
                            }
                        }

                        stage('Validate & Archive SBOM') {
                            steps {
                                sh '''
                                    echo "VALIDATING SBOM"
                                    cat sbom.cdx.json | jq empty

                                    COMPONENT_COUNT=$(cat sbom.cdx.json | jq '.components | length')
                                    echo "Generated SBOM with $COMPONENT_COUNT components"

                                    if [ "$COMPONENT_COUNT" -eq 0 ]; then
                                        echo "ERROR: No components found in SBOM!"
                                        exit 1
                                    fi
                                '''
                                archiveArtifacts artifacts: 'sbom.cdx.json,target/*.jar', fingerprint: true
                            }
                        }

                        stage('SBOM Validatie (BSI TR-03183-2)') {
                            steps {
                                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                    sh '''
                                        cd BAP
                                        git fetch origin
                                        git reset --hard origin/main
                                        python3 validate_sbom.py ../sbom.cdx.json
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('Dependency Check Flow') {
                    stages {
                        stage('Dependency Check scan') {
                            steps {
                                withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_API_KEY')]) {
                                    catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                        sh '''
                                            echo "STARTING OWASP DEPENDENCY-CHECK SCAN"
                                            curl -L https://github.com/dependency-check/DependencyCheck/releases/download/v12.1.0/dependency-check-12.1.0-release.zip -o dependency-check.zip
                                            unzip -q dependency-check.zip

                                            ./dependency-check/bin/dependency-check.sh \
                                                --project "spring-petclinic" \
                                                --scan ./target/spring-petclinic-4.0.0-SNAPSHOT.jar \
                                                --format HTML \
                                                --format JSON \
                                                --out ./dependency-check-report \
                                                --disableOssIndex \
                                                --nvdApiKey $NVD_API_KEY \
                                                --failOnCVSS 7
                                        '''
                                    }
                                }
                            }
                        }

                        stage('Publish Dependency Report') {
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
                }

                stage('SonarQube Flow') {
                    stages {
                        stage('SonarQube Scan') {
                            steps {
                                withSonarQubeEnv('SonarQube') {
                                    sh '''
                                        mvn sonar:sonar \
                                            -Dsonar.projectKey=spring-petclinic \
                                            -Dsonar.projectName="Spring Petclinic" \
                                            -Dsonar.java.binaries=target/classes \
                                            -q
                                    '''
                                }
                            }
                        }

                        stage('Quality Gate') {
                            steps {
                                timeout(time: 15, unit: 'MINUTES') {
                                    waitForQualityGate abortPipeline: true
                                }
                            }
                        }
                    }
                }

                stage('Grype Container Scan') {
                    stages {
                        stage('Install Grype') {
                            steps {
                                sh '''
                                    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b .
                                '''
                            }
                        }

                        stage('Scan Container Image') {
                            steps {
                                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                    sh '''
                                        echo "SCANNING CONTAINER IMAGE WITH GRYPE"
                                        ./grype ${IMAGE_NAME} --fail-on high -o table
                                    '''
                                }
                            }
                        }
                    }
                }

                stage('TruffleHog Secrets Scan') {
                    stages {
                        stage('Install TruffleHog'){
                            steps {
                                sh '''
                                    echo "SCANNING FOR SECRETS WITH TRUFFLEHOG"
                                    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b .
                                '''
                            }
                        }
                        
                        stage('Scan for Secrets') {
                            steps {
                                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                                sh '''
                                    ./trufflehog git file://. --only-verified --fail --json > trufflehog-report.json || true
                                '''
                                }
                                archiveArtifacts artifacts: 'trufflehog-report.json', fingerprint: true

                            }
                        }
                    }
                }
            }
        }

        stage('Run Container') {
            steps {
                sh '''
                    # Container wordt niet gerunt voordat hij gescanned is met Grype, vandaar na security tests pas
                    echo "RUNNING CONTAINER"
                    docker rm -f spring-petclinic || true
                    docker run -d --name spring-petclinic -p 9090:8080 ${IMAGE_NAME}
                    sleep 20
                    docker ps
                    docker logs spring-petclinic | tail -n 50
                '''
            }
        }

        // Extra: DAST
        stage('OWASP ZAP Scan') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        echo "STARTING OWASP ZAP DAST SCAN"
                        mkdir -p zap-report
                        chmod 777 zap-report
                        docker ps -a
                        docker ps
                        docker ps --format '{{.Names}}'


                        HOST_PATH="$(docker inspect $(hostname) --format='{{ range .Mounts }}{{ if eq .Destination "/var/jenkins_home" }}{{ .Source }}{{ end }}{{ end }}')/workspace/Proof of Concept/zap-report"

                        docker run --rm \
                            --add-host=host.docker.internal:host-gateway \
                            -v  ${HOST_PATH}:/zap/wrk:rw \
                            -u root\
                            ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                                -t http://host.docker.internal:9090 \
                                -r zap-report.html \
                                -J zap-report.json \
                                -d \
                                -I

                        chmod -R 777 zap-report
                        ls -la zap-report
                    '''
                }
                publishHTML(target: [
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'zap-report',
                    reportFiles: 'zap-report.html',
                    reportName: 'OWASP ZAP DAST Report'
                ])
                archiveArtifacts artifacts: 'zap-report/**', fingerprint: true
            }
        }
        stage('Compliance Rapport') {
            steps {
                publishHTML(target: [
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'compliance-report',
                    reportFiles: 'compliance-report.html',
                    reportName: 'CRA Compliance Rapport'
                ])
            }
        }

        stage('Archive Artifacts') {
            steps {
                archiveArtifacts artifacts: '''
                    sbom.cdx.json,
                    compliance-report/**,
                ''', fingerprint: true
            }
        }
    }

    post {
        failure {
            withCredentials([
                string(credentialsId: 'gmail-username', variable: 'GMAIL_USER'),
                string(credentialsId: 'gmail-app-password', variable: 'GMAIL_PASSWORD')
            ]) {
                sh '''
                    pwd
                    ls
                    git clone https://github.com/EngelsIlan/BAP.git
                    ls BAP
                    cd BAP
                    python3 send_mail.py "$GMAIL_USER" "$GMAIL_PASSWORD" "${JOB_NAME}" "${BUILD_NUMBER}" "${BUILD_URL}"
                '''
            }
        }
        always {
            sh 'docker rm -f spring-petclinic || true'
            sh 'docker rmi ${IMAGE_NAME} || true'
            cleanWs()
        }
    }
}