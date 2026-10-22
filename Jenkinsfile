// Jenkins pipeline equivalent to .github/workflows/ci.yml, for teams that run
// Jenkins. Requires: Docker (with the Compose plugin), kubectl and Python 3 on
// the agents, the Docker Pipeline and JUnit plugins, and (for publishing) a
// "ghcr-credentials" username/token credential.

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
        PROM_IMAGE  = 'prom/prometheus:v3.15.0'
        JAEGER_IMAGE = 'jaegertracing/jaeger:2.22.0'
        PG_IMAGE    = 'postgres:17.11-alpine'
        CRD_SCHEMAS = 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
        REGISTRY    = 'ghcr.io/arya-9989/secure-cloud-microservices-platform'
    }

    stages {
        stage('Verify') {
            parallel {
                stage('auth-service') {
                    agent any
                    steps {
                        script {
                            // Like CI, the suite runs against PostgreSQL (the refresh-token
                            // concurrency tests need real row locks).
                            docker.image(env.PG_IMAGE).withRun('-e POSTGRES_PASSWORD=ci-only-password -e POSTGRES_DB=auth') { pg ->
                                docker.image(env.UV_IMAGE).inside("--link ${pg.id}:postgres -e UV_CACHE_DIR=/tmp/uv-cache " +
                                        '-e DATABASE_URL=postgres://postgres:ci-only-password@postgres:5432/auth') {
                                    dir('services/auth-service') {
                                        sh 'uv sync --locked'
                                        sh 'uv run ruff check . && uv run ruff format --check .'
                                        sh 'uv run mypy .'
                                        sh '''
                                            for i in $(seq 1 30); do
                                                uv run python -c "import os, psycopg; psycopg.connect(os.environ['DATABASE_URL']).close()" && break
                                                sleep 2
                                            done
                                        '''
                                        sh 'uv run pytest --cov --cov-report=term-missing:skip-covered --junitxml=reports/junit.xml'
                                        sh '''
                                            uv export --locked --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt
                                            uv run pip-audit --strict --disable-pip --requirement /tmp/requirements.txt
                                        '''
                                    }
                                }
                            }
                        }
                    }
                    post {
                        always { junit 'services/auth-service/reports/junit.xml' }
                    }
                }

                stage('landing') {
                    agent {
                        docker { image 'node:24.19.0-alpine3.24' }
                    }
                    steps {
                        dir('services/landing') {
                            sh 'for f in site/assets/*.js; do node --check "$f"; done'
                            sh 'node --test'
                        }
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

                stage('Platform config') {
                    agent any
                    steps {
                        sh '''
                            kubectl kustomize deploy/k8s > k8s.yaml
                            docker run --rm -i ghcr.io/yannh/kubeconform:v0.7.0 \
                                -strict -summary -kubernetes-version 1.33.0 \
                                -schema-location default -schema-location "$CRD_SCHEMAS" - < k8s.yaml
                            for args in "check config /etc/prometheus/prometheus.yml" "test rules /etc/prometheus/alerts.test.yml"; do
                                docker run --rm -v "$PWD/observability/prometheus:/etc/prometheus:ro" \
                                    --entrypoint promtool "$PROM_IMAGE" $args
                            done
                            docker run --rm -v "$PWD/observability/jaeger:/etc/jaeger:ro" \
                                "$JAEGER_IMAGE" validate --config /etc/jaeger/config.yaml
                            python3 scripts/init_env.py --force
                            docker compose config --quiet
                        '''
                        sh '''
                            docker run --rm -v "$PWD:/src" -w /src -e UV_CACHE_DIR=/tmp/uv-cache "$UV_IMAGE" sh -c '
                                uv sync --locked --project tests/e2e &&
                                uv run --project tests/e2e ruff check tests/e2e scripts &&
                                uv run --project tests/e2e ruff format --check tests/e2e scripts &&
                                cd tests/e2e && uv run mypy .'
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
                            ['auth-service', 'orders-service', 'landing'].each { svc ->
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
                        JAEGER_PORT          = '17686'
                        COMPOSE_PROFILES     = 'tracing'
                        TRACING_ENABLED      = 'true'
                    }
                    steps {
                        sh 'python3 scripts/init_env.py --force'
                        sh 'docker compose up --no-build --wait --wait-timeout 300'
                        sh '''
                            docker run --rm --network host -v "$PWD:/src" -w /src/tests/e2e \
                                -e GATEWAY_URL=http://localhost:18080 -e GATEWAY_HTTPS_URL=https://localhost:18443 \
                                -e PROMETHEUS_URL=http://localhost:19090 -e GRAFANA_URL=http://localhost:13000 \
                                -e JAEGER_URL=http://localhost:17686 -e TRACING_ENABLED=true \
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
