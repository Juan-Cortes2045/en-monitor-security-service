# Architecture

`security-service` follows **Hexagonal Architecture (Ports and Adapters)**. The goal is to keep business logic isolated from frameworks and technical details, so the domain can be tested, understood, and evolved independently of Spring, JPA, or HTTP.

## Layers

```
security-service
│
├── adapter
│   ├── in
│   │   └── web            → Controllers (entry points)
│   └── out
│       ├── client         → External service clients (e.g. email)
│       ├── persistence    → JPA repositories, entities, mappers
│       └── security       → Technical security implementations (JWT, hashing)
│
├── application
│   ├── port
│   │   ├── in             → Input ports (not yet defined; use cases act as entry contracts)
│   │   └── out            → Output ports (interfaces the application depends on)
│   └── usecase             → Use cases (application logic coordinators)
│
├── domain
│   ├── model               → Domain models (business entities)
│   ├── valueobject          → Value objects
│   └── exception            → Domain exceptions
│
└── infrastructure
    ├── config              → Spring Security, OAuth2, OpenAPI configuration
    ├── exception           → Global exception handling
    └── observability       → Monitoring/observability concerns
```

### Domain

The core of the business. Contains domain models, value objects, and domain exceptions. It has **no dependency on Spring, JPA, HTTP, or any external framework** — this layer should compile and be testable in complete isolation.

Current domain models:

```
Person, User, UserConfiguration, PasswordResetToken, UserSession,
SecurityConfiguration, PasswordPolicy, LoginErrorLog (ErrorLog),
Role, Permission, Audit
```

Value objects:

```
UserStatus, LoginErrorType, AuditAction
```

Domain exceptions:

```
AccountBlockedException, AccountInactiveException, InvalidCredentialsException,
TokenAlreadyUsedException, TokenExpiredException, UserNotFoundException
```

### Application

Coordinates use cases — the operations the system exposes. A use case orchestrates domain models and output ports; it does not contain persistence, HTTP, or framework-specific code.

Current use cases:

```
AssignPermissionToRoleUseCase      LogoutUseCase
AssignRoleUseCase                  RefreshSessionUseCase
AuthenticateUserUseCase            RegisterAuditUseCase
AuthorizeUserUseCase               RegisterLoginErrorUseCase
CreateUserUseCase                  RequestPasswordResetUseCase
DeleteAccountUseCase               ResetPasswordUseCase
                                    RevokeSessionUseCase
                                    UpdatePasswordPolicyUseCase
                                    UpdateSecurityConfigurationUseCase
                                    UpdateUserConfigurationUseCase
                                    UpdateUserProfileUseCase
```

Output ports (interfaces implemented by adapters):

```
UserRepository, SessionRepository, PasswordResetTokenRepository,
PasswordPolicyRepository, SecurityConfigurationRepository,
LoginErrorLogRepository, RoleRepository, PermissionRepository,
AuditRepository, PasswordHasher, TokenProvider, EmailSender
```

New use cases should only be added when they represent a **relevant business operation** — not simply as a wrapper around a single entity method.

### Adapter — in (web and mobile)

Entry points that receive external requests (HTTP) and translate them into use case calls. Controllers must stay thin: they receive the request, call a use case, and return a response — no business logic here.

```
AuditController, AuthController, PasswordController, PermissionController,
RoleController, SecurityConfigurationController, SessionController, UserController
```

### Adapter — out (persistence, security, client)

Implements the output ports defined in `application/port/out`. This is where JPA, technical security, and external clients live.

- **persistence** — `*RepositoryAdapter` classes implement the output ports; they delegate to Spring Data `*JpaRepository` interfaces and use `*Mapper` classes to convert between domain models and JPA `*Entity` classes.
- **security** — `JwtTokenProvider` implements `TokenProvider`; `PasswordHasherImpl` implements `PasswordHasher`.
- **client** — `EmailSenderClient` implements `EmailSender`.

### Infrastructure

Cross-cutting configuration: `SecurityConfig`, `AuthorizationServerConfig`, `OpenApiConfig`, global exception handling, and observability setup. This is where Spring-specific wiring lives, kept separate from business logic.

## Request flow

```
HTTP Request
     ↓
Controller (adapter/in/web)
     ↓
Use Case (application/usecase)
     ↓
Domain (domain/model)
     ↓
Output Port (application/port/out)
     ↓
Adapter (adapter/out/persistence | security | client)
```

## Domain model separation: entity vs. persistence

Domain models and JPA entities are intentionally different classes, connected through a mapper. This keeps persistence details (JPA annotations, relationships, lazy loading) out of the domain.

```
Domain Model  ↔  Mapper  ↔  Persistence Entity

User          ↔  UserMapper  ↔  UserEntity
```

The application layer only knows the domain model and the repository port (`UserRepository`) — it never depends on the JPA repository (`UserJpaRepository`) or the entity (`UserEntity`) directly.

## Security responsibilities inside this microservice

`Security` is treated as a single **bounded context**, not split into several smaller microservices. Authentication, authorization, sessions, credentials, and auditing all live inside `security-service`, separated internally by layers rather than by deployment unit.

- **Authentication** answers: *who is the user?*
- **Authorization** answers: *what can the user do?*

Authorization here uses **RBAC (Role-Based Access Control)**:

```
User → UserSystemRole → SystemRole → SystemRolePermission → Permission
```

`SystemRole` (e.g. `ADMIN`, `USER`) is a **global system role**, managed entirely within `security-service`. It is a different concept from a "Home Role" (e.g. `OWNER`, `MEMBER`), which will belong to the Home microservice and represents a user's role within a specific household — the two must never be mixed.

## Boundaries with other microservices

- Each domain (Security, Home, Devices, Measurements, Notifications, Recommendations) is developed and versioned in its **own Git repository**.
- All microservices currently share a single physical **MySQL** database, organized logically by domain. This is a deployment convenience, not a license to share code.
- **Database schema migrations live in a separate repository.** `security-service` only connects to an already-migrated schema using connection credentials — it does not own or manage the schema.
- No microservice may import another microservice's entities, repositories, or internal classes directly (e.g. Home Service must never import `UserEntity` or `UserRepository` from Security). Cross-domain communication happens through **APIs, events, or well-defined contracts**, referencing other domains by ID only.
- Physical database separation per microservice may happen in the future; it is not a current requirement.

## Working principles

1. Preserve the Hexagonal / Ports and Adapters structure.
2. Keep the domain free of Spring/JPA dependencies.
3. No business logic in controllers or JPA entities.
4. Use ports for external dependencies; implement them via adapters.
5. Use mappers between domain and persistence.
6. Use cases coordinate application logic — avoid duplicating or over-fragmenting them.
7. Do not restructure existing packages without justifying a real problem first.
8. Never import another domain's entities or repositories directly.