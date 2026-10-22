// Jenkins pipeline equivalent to .github/workflows/ci.yml, for teams that run
// Jenkins. Requires: Docker on the agents, the Docker Pipeline and JUnit
// plugins, and (for publishing) a "ghcr-credentials" username/token credential.

pipeline {
    agent none

    options {
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds(abortPrevious: true)
    }

    environment {
        TRIVY_IMAGE = 'aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'
        UV_IMAGE    = 'ghcr.io/astral-sh/uv:0.13.5-python3.12-trixie-slim'
        REGISTRY    = 'ghcr.io/arya-9989/secure-cloud-microservices-platform'
    }

    stages {
        stage('Verify') {
            parallel {
                stage('auth-service') {
                    agent {
                        docker {
                            image 'ghcr.io/astral-sh/uv:0.13.5-python3.12-trixie-slim'
                            args '-e UV_CACHE_DIR=/tmp/uv-cache'
                        }
                    }
                    steps {
                        dir('services/auth-service') {
                            sh 'uv sync --locked'
                            sh 'uv run ruff check . && uv run ruff format --check .'
                            sh 'uv run mypy .'
                            sh 'uv run pytest --junitxml=reports/junit.xml'
                            sh '''
                                uv export --locked --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt
                                uv run pip-audit --strict --disable-pip --requirement /tmp/requirements.txt
                            '''
                        }
                    }
                    post {
                        always { junit 'services/auth-service/reports/junit.xml' }
                    }
                }

                stage('orders-service') {
                    agent {
                        docker {
                            image 'eclipse-temurin:21.0.12.1_1-jdk-noble'
                            // Testcontainers starts PostgreSQL through the host's Docker daemon.
                            args '-v /var/run/docker.sock:/var/run/docker.sock -e HOME=/tmp'
                        }
                    }
                    steps {
                        dir('services/orders-service') {
                            sh './mvnw -B -ntp verify'
                        }
                    }
                    post {
                        always { junit 'services/orders-service/target/surefire-reports/*.xml' }
                    }
                }

                stage('Kubernetes manifests') {
                    agent any
                    steps {
                        sh '''
                            kubectl kustomize deploy/k8s > k8s.yaml
                            docker run --rm -i ghcr.io/yannh/kubeconform:v0.7.0 \
                                -strict -summary -kubernetes-version 1.33.0 - < k8s.yaml
                        '''
                    }
                }
            }
        }

        // Build, e2e and publish run sequentially on ONE agent so the images
        // built and scanned here are exactly the ones tested and pushed.
        stage('Package, test & publish') {
            agent any
            stages {
                stage('Build & scan images') {
                    steps {
                        script {
                            ['auth-service', 'orders-service'].each { svc ->
                                // Also tagged with the name compose.yaml uses, so e2e runs these exact images.
                                sh "docker build --tag ${svc}:${env.GIT_COMMIT} --tag secure-platform/${svc}:local services/${svc}"
                                sh """docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ${TRIVY_IMAGE} \
                                      image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
                                      --exit-code 1 ${svc}:${env.GIT_COMMIT}"""
                            }
                        }
                    }
                }

                stage('End-to-end') {
                    environment {
                        COMPOSE_PROJECT_NAME = "secure-platform-${env.BUILD_NUMBER}"
                        GATEWAY_HTTP_PORT    = '18080'
                        GATEWAY_HTTPS_PORT   = '18443'
                        PROMETHEUS_PORT      = '19090'
                        GRAFANA_PORT         = '13000'
                    }
                    steps {
                        sh 'python3 scripts/init_env.py --force'
                        sh 'docker compose up --no-build --wait --wait-timeout 300'
                        sh '''
                            docker run --rm --network host -v "$PWD:/src" -w /src/tests/e2e \
                                -e GATEWAY_URL=http://localhost:18080 -e GATEWAY_HTTPS_URL=https://localhost:18443 \
                                -e PROMETHEUS_URL=http://localhost:19090 -e GRAFANA_URL=http://localhost:13000 \
                                "$UV_IMAGE" uv run --locked pytest -v --junitxml=reports/junit.xml
                        '''
                    }
                    post {
                        always {
                            junit allowEmptyResults: true, testResults: 'tests/e2e/reports/junit.xml'
                            sh 'docker compose logs --no-color --tail 200 > compose.log || true'
                            archiveArtifacts artifacts: 'compose.log', allowEmptyArchive: true
                            sh 'docker compose down --volumes --remove-orphans'
                        }
                    }
                }

                stage('Publish') {
                    when { branch 'main' }
                    steps {
                        withCredentials([usernamePassword(credentialsId: 'ghcr-credentials',
                                                          usernameVariable: 'REGISTRY_USER',
                                                          passwordVariable: 'REGISTRY_TOKEN')]) {
                            sh 'echo "$REGISTRY_TOKEN" | docker login ghcr.io -u "$REGISTRY_USER" --password-stdin'
                            script {
                                ['auth-service', 'orders-service'].each { svc ->
                                    sh """
                                        docker tag ${svc}:${env.GIT_COMMIT} ${REGISTRY}/${svc}:sha-${env.GIT_COMMIT}
                                        docker tag ${svc}:${env.GIT_COMMIT} ${REGISTRY}/${svc}:main
                                        docker push ${REGISTRY}/${svc}:sha-${env.GIT_COMMIT}
                                        docker push ${REGISTRY}/${svc}:main
                                    """
                                }
                            }
                        }
                    }
                    post {
                        always { sh 'docker logout ghcr.io || true' }
                    }
                }
            }
        }
    }
}
