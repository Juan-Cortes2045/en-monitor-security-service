# security-service

Identity and security microservice for the **Electric Consumption Monitor** project.

## Description

`security-service` is the microservice responsible for identity, authentication, session management, authorization (RBAC), and auditing within the **Electric Consumption Monitor** ecosystem — a hybrid hardware/software system (ESP32 + PZEM-004T V3) for monitoring, analyzing, and visualizing a household's electricity consumption.

Within the overall microservices architecture, this service acts as the **Security bounded context**, concentrating the following responsibilities in a single deployment unit:

- User identity (`Person`, `User`)
- Authentication and credential management
- Sessions (`UserSession`, refresh tokens)
- Password recovery
- Security configuration and password policies
- Role-based access control (RBAC)
- System auditing

The other domains of the system (Home, Devices, Measurements, Notifications, Recommendations) are independent microservices that communicate with `security-service` through well-defined contracts and APIs, without accessing its entities or tables directly.

## Architecture

The service follows **Hexagonal Architecture (Ports and Adapters)**, separating:

- `domain` — business models, value objects, and exceptions, with no framework dependencies.
- `application` — use cases and ports (inbound/outbound) that coordinate business logic.
- `adapter` — inbound adapters (web controllers) and outbound adapters (JPA persistence, technical security, email delivery).
- `infrastructure` — cross-cutting configuration (Spring Security, OpenAPI, exception handling, observability).

Full architectural details will be documented in `ARCHITECTURE.md`.

## Tech stack

- **Language:** Java 21
- **Framework:** Spring Boot 4.1.1
- **Persistence:** Spring Data JPA
- **Security:** Spring Security, OAuth2 (Authorization Server, Resource Server, Client)
- **Validation:** Spring Validation
- **API documentation:** OpenAPI

> Database schema migrations are managed in a separate repository. `security-service` only connects to an already-migrated schema.

## Current status

This repository currently holds the **initial project skeleton**: the complete hexagonal package structure, with classes and contracts defined but no business logic implemented yet.

## Working conventions

This project follows a Git workflow based on `main` / `dev` / `feat` / `fix` / `chore` / `hotfix` branches and Conventional Commits. See `git-conventions.md` before contributing.

## Team

| Team member | Main role | Additional roles |
|---|---|---|
| Juan Esteban Cortes Parra | Project Lead / DB Manager | Backend Developer, API & Cloud Developer, Tester |
| Miguel Ángel García Artunduaga / Juan Esteban Cortez Parra | Developer | Backend Developer, API & Cloud Developer |
| Miguel Ángel García Artunduaga | Analyst | Frontend Developer, Tester / UX-UI Designer |