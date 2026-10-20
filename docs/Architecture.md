# Architecture

`security-service` follows **Hexagonal Architecture (Ports and Adapters)**. Business logic stays
isolated from frameworks and technical details, so the domain can be tested, understood and
evolved independently of Spring, JPA or HTTP.

The code is the `security` module of `energy-monitor-backend`, moved out unchanged in its
structure: same package (`com.energymonitor.security`), same use cases, same tests.

## Layers

```
com.energymonitor.security
│
├── api                     → Contracts for other services: account events, profile and
│                             administrator queries, mail delivery requests
├── domain
│   ├── model               → Domain models, value objects and domain exceptions
│   └── service             → Domain services (pure rules, no framework)
├── application
│   ├── command, result     → Input and output of the use cases
│   ├── exception           → Application exceptions
│   ├── port/in             → Use case interfaces
│   ├── port/out            → Interfaces the application depends on
│   └── usecase             → Use case implementations (no Spring annotations)
├── adapter
│   ├── in/web              → AuthController, AdminController, SecurityExceptionHandler
│   └── out
│       ├── persistence     → JPA entities, Spring Data repositories, mappers, adapters
│       ├── security        → BCrypt, token generation and hashing, Google OAuth client
│       ├── event           → Account event publisher
│       └── mail            → Mail delivery requests (see "Migration status")
└── infrastructure          → Spring wiring: filter chain, JWT, CORS, RBAC authorization,
                              executors and configuration properties
```

### Domain

The core of the business. It has **no dependency on Spring, JPA, HTTP or any external
framework**, so it compiles and is testable in isolation.

### Application

A use case orchestrates domain models and output ports; it contains no persistence, HTTP or
framework code. The use cases are plain classes, wired in `SecurityApplicationWiring`, and the
transaction boundaries are applied there, not inside the use cases.

### Adapters

- **in/web** — thin controllers under `/api/v1/auth/**` and `/api/v1/admin/users|roles/**`, and
  one exception handler that renders every error in the shared shape.
- **out/persistence** — adapters implementing the output ports; they delegate to Spring Data
  repositories and convert between domain models and JPA entities through mappers.
- **out/security** — password hashing, secure tokens and identifiers, the pepper-based hash of
  recovery codes, the attempt limiter and the Google OAuth client.
- **out/event** — publishes `AccountRegistered`, `AccountAdministered` and `AccountDeleted`.
- **out/mail** — hands verification and recovery codes to the mail channel.

### Infrastructure

The filter chain (stateless, bearer tokens only, everything denied unless permitted on purpose),
the RS256 key pair and the token issuer, CORS, the live RBAC check of the admin routes, and the
configuration properties.

## Tokens

This service is the only one that **signs** tokens, so it is the only one holding the private key.

- Access token: JWT RS256, 15 minutes, `iss = https://energy-monitor-backend`, `sub` = the
  account. It carries no roles: permissions are resolved from the database on every request.
- Refresh token: opaque, stored as a hash, rotated on every use, with reuse detection by family.

The other services validate access tokens with the **public key** only.

## RBAC

```
User → UserSystemRole → SystemRole → SystemRolePermission → Permission
```

`ADMIN` is a **global role** seeded by `security-025` with `USER.READ`, `USER.MANAGE` and
`ROLE.MANAGE`. It is a different concept from a home role (`OWNER`, `MEMBER`), which belongs to
energy-monitor-backend; the two are never mixed, and the global role grants no access to any home.

## Database

- The service uses the **same MySQL schema** as energy-monitor-backend (ADR-003) and owns the
  security tables.
- Its changesets (`security-001` to `security-025`) live here, under the **same relative path**
  they had in the monolith (`db/changelog/security/...`). Liquibase identifies a changeset by id,
  author and file path, so the ones already applied are recognised and never run again.
- Both services share the `DATABASECHANGELOG` table; each one applies only its own changelogs.
- A new schema change is always a new changeset with its `rollback`.

## Boundaries with other services

- No service imports another one's entities, repositories or internal classes. Other domains are
  referenced by identifier only.
- Communication goes through the contracts in `api`: queries over internal REST endpoints and
  state changes as events over the message broker (see "Migration status").

## Migration status

| Phase | Content | Status |
|---|---|---|
| 1 | Module moved here with its tests and changesets | Done |
| 2 | RabbitMQ, transactional outbox and events; mail requests over the broker | Pending |
| 3 | `/internal` endpoints (permissions, profiles, administrators) and the deletion check | Pending |
| 4 | `security` removed from energy-monitor-backend | Pending |
| 5 | API gateway | Pending |
| 6 | Infrastructure, CI/CD and deployment | Pending |

Until phase 2, `UnroutedMailDeliveryAdapter` only logs that a code was not sent (never the code
itself), and the account events have no listener outside this service.

## Working principles

1. Preserve the Hexagonal / Ports and Adapters structure.
2. Keep the domain free of Spring and JPA dependencies.
3. No business logic in controllers or JPA entities.
4. Use ports for external dependencies; implement them through adapters.
5. Use mappers between domain and persistence.
6. Never import another domain's entities or repositories.
