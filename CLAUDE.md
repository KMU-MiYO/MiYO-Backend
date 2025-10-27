# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
MiYO-Backend is a Spring Boot 3.5.5 application using Java 17, MySQL, and JPA. The application is deployed on Naver Cloud Platform (NCP) using Kubernetes with CI/CD via GitHub Actions.

## Common Commands

### Build and Run
```bash
# Build the project
./gradlew build

# Run tests
./gradlew test

# Run the application locally
./gradlew bootRun

# Clean build artifacts
./gradlew clean
```

### Docker
```bash
# Build Docker image
docker build -t miyo-backend .

# Run Docker container
docker run -p 8080:8080 \
  -e MYSQL_HOST=<mysql-host> \
  -e DB_NAME=<database-name> \
  -e SPRING_DATASOURCE_PASSWORD=<password> \
  miyo-backend
```

### Kubernetes
```bash
# Apply deployment
kubectl apply -f k8s-deployment.yml

# Apply service
kubectl apply -f k8s-service.yml

# Check deployment status
kubectl get deployments
kubectl get pods
```

## Architecture

### Technology Stack
- **Framework**: Spring Boot 3.5.5
- **Java Version**: 17
- **Build Tool**: Gradle
- **Database**: MySQL 8 with JPA/Hibernate
- **Deployment**: Kubernetes on Naver Cloud Platform

### Configuration
- Database configuration uses environment variables: `MYSQL_HOST`, `DB_NAME`, `SPRING_DATASOURCE_PASSWORD`
- Application properties in `src/main/resources/application.properties`
- JPA configured with `ddl-auto=none` (manual schema management)
- SQL logging enabled with `show-sql=true` and formatted output

### Deployment Strategy
- Rolling update strategy with `maxUnavailable: 0` and `maxSurge: 1` for zero-downtime deployments
- Container image hosted at `contest90.kr.ncr.ntruss.com/contest90-backend`
- Uses Kubernetes secrets for MySQL password (`test-mysql-secret`)

## CI/CD Pipeline
GitHub Actions workflow (`.github/workflows/ci.yaml`) triggers on:
- Push to `main`, `*/main`, `*/develop`, `*/feature/**` branches
- Pull requests to the same branches

Pipeline steps:
1. Checkout code
2. Set up JDK 17 with Gradle cache
3. Build with `./gradlew build`

## PR Conventions
Use these prefixes in PR titles:
- `[FEAT]` - New features
- `[FIX]` - Bug fixes
- `[CHORE]` - Configuration, dependencies, non-code changes
- `[DOCS]` - Documentation updates
- `[REFACTOR]` - Code refactoring without functionality changes
- `[MODIFY]` - Code modifications with functionality changes

## Package Structure
- Base package: `io.github.herbpot.miyobackend`
- Main application class: `MiYoBackendApplication.java`
