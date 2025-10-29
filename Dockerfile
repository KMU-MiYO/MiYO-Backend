# Multi-stage build for smaller image size
FROM openjdk:17-jdk-slim AS builder

# Set working directory
WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

COPY src src

RUN chmod +x ./gradlew
RUN ./gradlew build -x test --no-daemon --no-watch-fs

# Runtime stage
FROM openjdk:17-jdk-slim

# Install curl for healthcheck
RUN apk add --no-cache curl

# Set working directory
WORKDIR /app

# Copy built jar from build stage
COPY --from=build /app/build/libs/MiYO-Backend-0.0.1-SNAPSHOT.jar app.jar

# Change ownership
RUN chown -R spring:spring /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

# Run application
ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=${SPRING_PROFILE:local}", "app.jar"]
