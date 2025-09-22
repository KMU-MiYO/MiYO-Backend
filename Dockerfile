FROM openjdk:17-jdk-slim AS builder

WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

COPY src src

RUN chmod +x ./gradlew
RUN ./gradlew build --no-daemon --no-watch-fs

FROM openjdk:17-jdk-slim

WORKDIR /app

COPY --from=builder /app/build/libs/MiYO-Backend-0.0.1-SNAPSHOT-plain.jar ./app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
