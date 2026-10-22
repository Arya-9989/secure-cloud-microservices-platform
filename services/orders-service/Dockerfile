# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------- build
FROM eclipse-temurin:21.0.12.1_1-jdk-noble AS build
WORKDIR /src

# Resolve dependencies in their own layer, cached until the POM changes.
COPY mvnw pom.xml ./
COPY .mvn .mvn
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B -q dependency:go-offline -Dspotless.check.skip=true

COPY src src
# Tests and formatting checks run in CI before the image is built.
RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -B -q package -DskipTests -Dspotless.check.skip=true \
 && java -Djarmode=tools -jar target/orders-service.jar extract --layers --launcher --destination /extracted

COPY docker/HealthCheck.java /tmp/HealthCheck.java
RUN javac --release 21 -d /healthcheck /tmp/HealthCheck.java

# ---------------------------------------------------------------------------- runtime
# Distroless: no shell, no package manager, runs as uid 65532 ("nonroot").
FROM gcr.io/distroless/java21-debian13:nonroot AS runtime

LABEL org.opencontainers.image.title="orders-service" \
      org.opencontainers.image.description="Orders API: Spring Boot OAuth2 resource server" \
      org.opencontainers.image.source="https://github.com/Arya-9989/secure-cloud-microservices-platform" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
# Layers ordered from least to most frequently changing for better cache reuse.
COPY --from=build /extracted/dependencies/ ./
COPY --from=build /extracted/spring-boot-loader/ ./
COPY --from=build /extracted/snapshot-dependencies/ ./
COPY --from=build /extracted/application/ ./
COPY --from=build /healthcheck /opt/healthcheck

USER nonroot
EXPOSE 8080 8081

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=3 \
  CMD ["java", "-XX:TieredStopAtLevel=1", "-XX:+UseSerialGC", "-Xmx16m", "-Xss512k", \
       "-cp", "/opt/healthcheck", "HealthCheck", "http://127.0.0.1:8081/actuator/health/liveness"]

ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", \
            "-Djava.security.egd=file:/dev/./urandom", \
            "org.springframework.boot.loader.launch.JarLauncher"]
