# Multi-stage build for smaller image size
FROM openjdk:17-jdk-slim AS builder
RUN apk add --no-cache dumb-init

# Set working directory
WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

COPY src src

# Fix line endings and set execute permission
RUN sed -i 's/\r$//' ./gradlew && chmod +x ./gradlew

# Build with Gradle (with retry and resource limits)
RUN ./gradlew build -x test --no-daemon --no-watch-fs --stacktrace

# Runtime stage
FROM openjdk:17-jdk-slim


# Set working directory
WORKDIR /app

# Copy built jar from build stage
COPY --from=builder /app/build/libs/MiYO-Backend-0.0.1-SNAPSHOT.jar app.jar

# Run application
ENTRYPOINT ["java", "-jar", "app.jar"]
