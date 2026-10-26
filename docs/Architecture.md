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
│       └── messaging       → Transactional outbox, relay and RabbitMQ publisher
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
- **out/messaging** — the account events and the mail requests, written to the outbox and
  relayed to RabbitMQ (see "Messaging").

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

## Messaging

Everything other services must hear from this one goes to the topic exchange
`energy-monitor.security`, with the message type as routing key:

| Routing key | Body (JSON) | Consumer in energy-monitor-backend |
|---|---|---|
| `account.registered` | `userId`, `email`, `occurredAt` | notification: in-app notice to the administrators |
| `account.administered` | `actorId`, `userId`, `action`, `detail`, `occurredAt` | notification: in-app notice to the other administrators |
| `account.deleted` | `userId`, `deletedAt` | home: drops the memberships and the homes it alone owned |
| `mail.email-verification` | `userId`, `recipient`, `code`, `validUntil` | notification: mails the code |
| `mail.password-reset` | `userId`, `recipient`, `idResetToken`, `code`, `validUntil` | notification: mails the code |

- **Transactional outbox.** A message is written to `security_outbox` (changeset
  `security-026`) in the same transaction as the change it announces, so a change is never
  committed without its message and a rolled back change never sends one.
- **Relay.** Every second, `OutboxRelay` publishes the pending messages oldest first. A message
  counts as published only when RabbitMQ confirms it and a queue took it; the first failure stops
  the run, so order is kept and the message is retried. Delivery is therefore at least once, and
  every message carries its id (`message_id`) so consumers drop duplicates.
- **Codes.** A mail request holds a code in clear text. Its payload is erased as soon as the
  broker confirms it, it expires with the code (AMQP expiration), and the relay discards it unsent
  once the code is no longer valid.
- **Queues.** The consumers declare their own durable queues, each with a dead-letter queue.
- **Single instance.** The relay assumes one instance of this service; a second one would keep
  delivery correct but could reorder messages.

## Internal API

What energy-monitor-backend asks this service while it serves its own requests, and what this
service asks it back. Neither side presents a JWT: a call is trusted only when it comes from
`internal-api.allowed-networks` **and** carries `internal-api.token` (`INTERNAL_API_TOKEN`, the
same in both services) in `X-Internal-Token`, compared in constant time. Without a token
configured every internal call is refused. The API gateway never forwards `/internal/**`.

| Direction | Route | Answer |
|---|---|---|
| backend → security | `GET /internal/users/{id}/permissions` | `{permissions: [...]}`; 404 without an active account |
| backend → security | `POST /internal/users/profiles` `{userIds}` (≤ 500) | `{profiles: [{userId, name, lastName, email}]}`, active accounts only |
| backend → security | `GET /internal/administrators` | `{userIds: [...]}` |
| security → home service | `GET /internal/accounts/{id}/deletion-check` | 204 may delete; 409 `{message}` refused |

- **Deleting an account.** The use case asks the deletion check after verifying the password and
  before changing anything. A 409 is returned to the user as is; no answer within 1 s to connect
  and 2 s to read, or any other status, refuses the deletion with 503. Once deleted,
  `account.deleted` tells the home service and the backend to clean up.
- **The backend's side** caches permissions and administrators 30 s and profiles 60 s (Caffeine),
  and degrades when this service does not answer: names are left out of the member list and the
  administrator notifications, alert mail is skipped (push still goes), its `/api/v1/admin/**`
  routes answer 503 and a message consumer lets the broker retry.
- **A deletion that slips past the check** (a member joined in between) does not block
  `account.deleted`: the home service hands the home to its oldest remaining member.

## Boundaries with other services

- No service imports another one's entities, repositories or internal classes. Other domains are
  referenced by identifier only.
- Communication goes through the contracts in `api`: queries over internal REST endpoints and
  state changes as events over the message broker (see "Migration status").
- The clients reach the services only through the API gateway, which validates the token before
  forwarding; each service validates it again and decides the permissions itself.

## Migration status

| Phase | Content | Status |
|---|---|---|
| 1 | Module moved here with its tests and changesets | Done |
| 2 | RabbitMQ, transactional outbox and events; mail requests over the broker | Done |
| 3 | `/internal` endpoints (permissions, profiles, administrators) and the deletion check | Done |
| 4 | `security` removed from energy-monitor-backend: it validates the tokens with the public key and asks this service the rest | Done |
| 5 | API gateway (`en-monitor-api-gateway`, :8080): routes, CORS, token check and rate limit in front of both services; energy-monitor-backend moves to :8083 | Done |
| 6 | Infrastructure, CI/CD and deployment: RabbitMQ, this service and the gateway in the infra compose files, the web nginx in front of the gateway, CI/CD workflows and `deploy.sh` for both | Done |


## Working principles

1. Preserve the Hexagonal / Ports and Adapters structure.
2. Keep the domain free of Spring and JPA dependencies.
3. No business logic in controllers or JPA entities.
4. Use ports for external dependencies; implement them through adapters.
5. Use mappers between domain and persistence.
6. Never import another domain's entities or repositories.
