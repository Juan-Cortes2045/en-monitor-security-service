# security-service

Identity and security microservice of **EnergyMonitor**, the household electricity monitor
(ESP32 + PZEM-004T V3).

It is the **Security bounded context**, moved out of `energy-monitor-backend`:

- Accounts (`Person`, `User`): registration, email verification, profile and account deletion
- Authentication: email and password, and Sign in with Google
- Sessions: JWT RS256 access tokens and rotating refresh tokens
- Password recovery with a six-digit code
- Global roles (RBAC) and user administration (`/api/v1/admin/users`, `/api/v1/admin/roles`)
- Audit trail

The architecture and the migration status are in [`docs/Architecture.md`](docs/Architecture.md).

## Tech stack

Java 21, Spring Boot 4.1.1, Spring Security with the OAuth2 resource server (JWT RS256), Spring
Data JPA, Liquibase, MySQL 8.4 and springdoc-openapi.

## Running locally

Requirements: Java 21 and the MySQL of the infra repository running
(`docker compose up -d mysql` in `infra`).

1. `cp .env.example .env` and fill in the `CHANGE_ME` values. `SPRING_DATASOURCE_PASSWORD` is the
   `MYSQL_PASSWORD` of `infra/.env`, and `SECURITY_RESET_PEPPER` must be the value the backend
   uses.
2. `cp src/main/resources/application-local.yaml.example src/main/resources/application-local.yaml`
   and set the database password and the paths of the RSA key pair.
3. `./mvnw spring-boot:run`

The service answers on `http://localhost:8082` (`SERVER_PORT`), so it can run next to
energy-monitor-backend on 8080. Health: `/actuator/health`; Swagger UI: `/swagger-ui.html`.

It does not start without the RSA key pair or the pepper.

## Tests

```bash
SPRING_DATASOURCE_PASSWORD=... ./mvnw test
```

The persistence tests run against the real MySQL of the infra repository, because Liquibase owns
the schema. Every test runs under the `test` profile (test-only pepper, key pair under
`~/.energy-monitor/keys`).

## Docker

```bash
docker build -t energy-monitor-security .
```

The infra repository orchestrates the image together with the rest of the platform.

## Working conventions

Git workflow based on `main` / `dev` / `feat` / `fix` / `chore` / `hotfix` branches and
Conventional Commits. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Team

| Team member | Main role | Additional roles |
|---|---|---|
| Juan Esteban Cortes Parra | Project Lead / DB Manager | Backend Developer, API & Cloud Developer, Tester |
| Miguel Ángel García Artunduaga / Juan Esteban Cortez Parra | Developer | Backend Developer, API & Cloud Developer |
| Miguel Ángel García Artunduaga | Analyst | Frontend Developer, Tester / UX-UI Designer |
