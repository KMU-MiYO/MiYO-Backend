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


# Set working directory
WORKDIR /app

# Copy built jar from build stage
COPY --from=builder /app/build/libs/MiYO-Backend-0.0.1-SNAPSHOT.jar app.jar

# Change ownership
RUN chown -R spring:spring /app

# Run application
ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=${SPRING_PROFILE:local}", "app.jar"]
