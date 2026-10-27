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
Data JPA, Liquibase, MySQL 8.4, Spring AMQP (RabbitMQ) and springdoc-openapi.

## Running locally

Requirements: Java 21, and the MySQL and RabbitMQ of the infra repository running. Without
RabbitMQ the service still starts, but the account events and mail requests wait in the outbox
and `/actuator/health` reports DOWN.

1. `cp .env.example .env` and fill in the `CHANGE_ME` values. `SPRING_DATASOURCE_PASSWORD` is the
   `MYSQL_PASSWORD` of `infra/.env`; generate `SECURITY_RESET_PEPPER` with `openssl rand -hex 32`
   (changing it later invalidates the codes already issued).
2. `cp src/main/resources/application-local.yaml.example src/main/resources/application-local.yaml`
   and set the database password and the paths of the RSA key pair (see "RSA key pair").
3. `./mvnw spring-boot:run`

The service answers on `http://localhost:8082` (`SERVER_PORT`), next to the API gateway on 8080
and energy-monitor-backend on 8083. The web and mobile apps call the gateway, not this port. Health: `/actuator/health`; Swagger UI: `/swagger-ui.html`.

It does not start without the RSA key pair or the pepper.

`INTERNAL_API_TOKEN` must be the value of energy-monitor-backend: it protects the internal calls
between both (see [docs/Architecture.md](docs/Architecture.md#internal-api)). Without it the
backend cannot ask for permissions or profiles, and deleting an account answers 503 because the
home service refuses the deletion check (`HOME_SERVICE_URL`).

## RSA key pair

The access tokens are signed with RS256 by this service, the only one holding the private key.
energy-monitor-backend validates them with the public key, so it is given `public.pem` only. The
`.pem` files are gitignored and must never be committed.

```bash
mkdir -p ~/.energy-monitor/keys && chmod 700 ~/.energy-monitor/keys
openssl genpkey -algorithm RSA -out ~/.energy-monitor/keys/private.pem -pkeyopt rsa_keygen_bits:2048
chmod 600 ~/.energy-monitor/keys/private.pem
openssl rsa -in ~/.energy-monitor/keys/private.pem -pubout -out ~/.energy-monitor/keys/public.pem
chmod 644 ~/.energy-monitor/keys/public.pem
```

On Windows run the same `openssl` commands from Git Bash, with `$HOME\.energy-monitor\keys`.
Point `SECURITY_JWT_PRIVATE_KEY_PATH` and `SECURITY_JWT_PUBLIC_KEY_PATH` at them, with absolute
paths (Java does not expand `~`). PKCS#1 keys (`openssl genrsa`) are also accepted. The service
refuses to start when a key is missing, unreadable or of the wrong kind, and names the path.

## Accounts, codes and roles

### The recovery code, and why it is short

`POST /api/v1/auth/password/forgot` answers **404** ("No account is registered with that email
address.") when no account uses the address, so the person knows to try another one, and otherwise
**202** while energy-monitor-backend mails a **six-digit code**, valid for 15 minutes and usable
once. Saying which addresses are registered is a deliberate choice: registration already answers
409 for a registered address, and the per-caller limit below is charged before the lookup. Six digits is a usability decision — a person has to read it off a screen and
type it back — and on its own it would be no defence at all, about 20 bits. Two
other things carry the weight:

- **A pepper.** What is stored in `password_reset_token.reset_token_hash` is
  `HMAC-SHA256(code, pepper)`, not a plain digest. A plain digest of a six-digit
  code can be reversed from a database dump in seconds: a million candidates, all
  cheap to hash. The pepper lives in the configuration, not in the table, so a
  leaked dump yields nothing usable.
- **A rate limit.** Ten redemption attempts per caller address per 15 minutes,
  counted whether the code presented was right or wrong. The endpoint answers `429`
  with `Retry-After` past that, which is what makes a small space survivable.

One further rule does a lot of quiet work: **issuing a code consumes whatever codes
the account already held.** With several outstanding, the rate limit would bound
guessing only after being multiplied by how many an attacker could first arrange to
have.

Generate the pepper with `openssl rand -hex 32` and set it as `SECURITY_RESET_PEPPER` in `.env`
(or `security.reset.pepper` in `application-local.yaml`). The application refuses to start without it, the same
way it refuses to start without a signing key. Changing it invalidates every code
already issued, and codes issued before the peppered digest was introduced can no
longer be redeemed.

What was deliberately **not** done: BCrypt. It is the obvious way to make a small
secret expensive, and it is wrong here for a structural reason — it is salted, so the
same code hashes differently every time, and redemption resolves a code to its row
*by* hashing the presented value. With BCrypt there would be nothing stable to look
up.

Known limits, stated plainly: the attempt counter lives in memory, so it is per
instance, resets on restart, and cannot be shared between replicas. Behind a load
balancer, add a rate limiter there too. And because the limit is keyed by address,
everyone behind one NAT shares it, which is why the allowance is generous enough to
absorb an office.

### Registration and the email verification code

**No account exists until its address is verified.** `POST /api/v1/auth/register` validates the
request and answers **202** with `{email, expiresAt}`; it writes no `person` and no `user` row.
It keeps the request in `pending_registration` (password hashed) and has energy-monitor-backend
mail a six-digit code to the address. `POST /api/v1/auth/email/verify` with `{email, code}` is what
creates the account: the person and the user, already verified, an audit `CREATE` entry and the
`account.registered` event, and the request is deleted. An address nobody reads therefore never
becomes an account: its request expires after **24 hours** and an hourly job deletes it
(`security.registration.purge-enabled=false` turns the job off).

- The request reserves the account's identifier, so the code (derived from it) and the
  delivery record of the mail already point at the account it becomes.
- Registering again with the same address replaces the request and invalidates its code (a
  mistyped password can be fixed that way). An address that already has an account gets **409**.
- `POST /api/v1/auth/email/verification/resend` sends the current code again, for a request or for
  an account whose address changed, and always answers `202`.

Before keeping a request, registration checks the domain of the address in two steps, and so
does a profile update that changes the email:

1. **Mistyped provider.** A domain one or two keystrokes away from a well-known provider
   (`meil.com` → `mail.com`, `gmial.con` → `gmail.com`, `hotmail.co` → `hotmail.com`) is refused
   with **400**, and the message names the provider it was probably meant to be. DNS cannot catch
   these: many are registered on purpose and publish real mail servers that collect whatever is
   sent to them. The providers and the tolerance are in `domain/service/MistypedEmailDomains`.
2. **Deliverable domain.** It must exist in DNS and publish a mail server (MX) or an address
   (A/AAAA). An invented domain is refused with **400** and nothing is stored. When DNS cannot
   be reached the address is let through (an outage must not stop registrations).
   `SECURITY_EMAIL_DOMAIN_CHECK_ENABLED=false` turns this step off; the test profile does, so the
   suite never needs the network.

Neither step proves that the mailbox exists: that cannot be asked reliably (most providers do not
tell, and probing them gets a server blacklisted). That is the verification code's job.

The code is derived, not stored: `HMAC-SHA256` with the same pepper, over the account identifier
(the reserved one for a request), the address and the current fifteen-minute window, reduced to
six digits. A code is accepted during its window and the next one, so it lives between 15 and 30
minutes, and changing the address invalidates it. Guessing is bounded twice: the per-address limit
above, and five attempts per address per window, so spreading guesses over many callers does not
help.

Signing in needs a verified address. With the right password, a request still waiting for its
code, or an account whose changed address is not verified yet, gets **403** ("Verify your email
address to sign in.") instead of a session. The check runs after the password, so only someone
who knows the password learns that the registration exists. The web app then asks for a new code
(`/email/verification/resend`) and takes the person to enter it; after `/email/verify` the sign-in
works. Accounts created with Google start verified and skip the request (they still accept the
terms and conditions, see below).

### Terms and conditions

No account signs in without having accepted the terms and conditions, whatever the method. The
acceptance is stored in `user.terms_accepted_at`.

- **Registration** needs `"acceptTerms": true`; without it the answer is **428** and nothing is
  stored. The account created at verification records the instant of the registration.
- **Google**: the first sign-in creates the account only with `"acceptTerms": true` in
  `POST /api/v1/auth/google`; without it the answer is **428** and nothing is created. The web
  then shows the terms and, if they are accepted, opens Google again (its code is single-use);
  the mobile app repeats the request with the same `idToken`. The registration page sends the
  checkbox it already shows.
- **Existing accounts** (`security-029`): accounts registered with a password accepted the terms
  in the form, which required the checkbox, so they take their registration date. Accounts
  created with Google before this were never asked: their next sign-in answers 428 until they
  accept.
- `POST /api/v1/auth/login` answers 428 the same way for an account without acceptance, and
  takes `"acceptTerms": true` to record it.

### Deleting an account

`POST /api/v1/auth/account/delete` with `{password}` deletes the caller's own account after
checking the password (`401` when it is wrong, `204` when done). It is a soft delete: `user` and
`person` get `deleted_at` and the account's sessions are closed. The address is released: the
deleted row keeps `deleted+<id_user>@deleted.invalid` instead, so the same address can register a
new account.

Before changing anything the service asks the home service whether the account may go
(`GET /internal/accounts/{id}/deletion-check`). If the account is the only owner of a home that
still has other members, the request is refused with `409` and the home service's readable
`message`: the ownership must be handed over or the members removed first. If the home service
does not answer, the answer is `503` and nothing is deleted. Once deleted, `account.deleted` tells
the home service to drop the memberships and the homes nobody else is left in, and the backend to
drop the account's notification preferences and devices. An access token issued before the
deletion keeps working until it expires, at most 15 minutes; no refresh token can renew it.

### Administrators and global roles (RBAC)

There are two kinds of roles, and they never mix:

- **Home roles** (`OWNER`, `MEMBER`) are kept per home by energy-monitor-backend and decide what a user
  may do *inside that home*.
- **Global roles** (RBAC: `system_role` → `system_role_permission` → `permission`, assigned
  through `user_system_role`) decide what a user may do *on the platform*. Today there is one,
  `ADMIN`, seeded by `security-025-seed-admin-role` with three permission codes:

| Code | Allows | Routes |
|---|---|---|
| `USER.READ` | read the user directory and the role list | `GET /api/v1/admin/users?q=&page=&size=` (size 1–50, default 20), `GET /api/v1/admin/roles` |
| `USER.MANAGE` | move another account to `ACTIVE`, `INACTIVE` or `BLOCKED` | `PUT /api/v1/admin/users/{idUser}/status` with `{"status":"BLOCKED"}` |
| `ROLE.MANAGE` | grant or revoke a global role | `PUT` / `DELETE /api/v1/admin/users/{idUser}/roles/{roleName}` |

How it behaves:

- The filter chain checks the code on every request, reading it from the database rather than
  from the token: a granted or revoked role, or a blocked account, takes effect on the next
  request. Without the code the answer is `403`; without a token, `401`. Any other
  `/api/v1/admin/**` route of this service is denied. energy-monitor-backend asks the same codes
  through `GET /internal/users/{id}/permissions` for its administrator notifications, and caches
  the answer 30 seconds.
- `ADMIN` gives **no access to any home**. An administrator who is not a member of a home cannot
  read it, exactly like any other user.
- An administrator cannot change their own status or roles (`409`), so nobody locks themselves
  out by accident; another administrator has to do it.
- Moving an account out of `ACTIVE` revokes its sessions, so it cannot refresh. Its current
  access token still works on the non-admin routes until it expires (at most 15 minutes).
- Every change is written to `audit_log`. `GET /api/v1/auth/permissions` returns the caller's
  codes; the web uses it to show or hide the administration screen.

**The first administrator.** No account is an administrator after installing: granting a global
privilege by default would hand the platform to whoever registered first. Register the account
normally, then grant it the role once with the script of the `infra` repository (it reads the
MySQL root password from `infra/.env`, and gives the role back if it had been revoked):

```bash
cd ../../infra   # from this repository
./make-admin.sh admin@example.com
```

Sign out and in again on the web, or reload it, and **Administration** appears in the menu. From there that administrator can grant
`ADMIN` to other accounts; the SQL is only needed for the first one. To undo it by hand:
`DELETE FROM user_system_role WHERE system_role_id = 'rol0000001' AND user_id = '<id_user>';`.

### Support contacts

`GET /api/v1/support/contacts` is public: the support page of the web app reads it before anyone
signs in. It answers the name and email address of every active administrator, sorted by name
(`[]` while there is none), so the page can write to the administrator, or let the person choose
one when there are several. Nothing else about the administrators is exposed.

### Sign in with Google

`POST /api/v1/auth/google {code}` exchanges the authorization code of Google's sign-in popup
(web app) for the usual access and refresh tokens. The mobile app signs in natively instead and
sends `POST /api/v1/auth/google {idToken}`: the ID token is checked like the one the code
returns (Google's signature, issuer, expiry, and audience = `GOOGLE_CLIENT_ID`), so the app must
request it with the **web** client id as `webClientId`. A body with both or neither is `400`. The first time it creates the account with the
first name, last name (when the Google account has one), photo and address of Google; the address
starts verified and the account gets a random password nobody knows ("forgot password" sets
one). An address that already belongs to an account registered with a password is refused with
**409**: signing in with Google never takes over an existing account.

Setup (once per environment):

1. <https://console.cloud.google.com> → create (or pick) a project.
2. **APIs & Services → OAuth consent screen** (Google Auth Platform → Branding/Audience):
   app name, support email, audience **External**. While the app is in *Testing*, add the Google
   accounts that may sign in under **Test users**. Scopes: `openid`, `email`, `profile`.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**, type **Web
   application**. *Authorized JavaScript origins*: `http://localhost:5173` (add the production
   domain later). No redirect URI is needed (the popup uses `postmessage`).
4. Put the client ID and secret in this `.env` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`) and the
   same client ID in the web app's `.env.local` (`VITE_GOOGLE_CLIENT_ID`); restart both. Both
   empty = the Google button answers `503`.
5. Mobile app: in the **same project**, create another OAuth client ID of type **Android** with
   the package `com.energymonitor.mobile` and the SHA-1 of the key that signs the APK
   (`apksigner verify --print-certs app-release.apk`). The app sends the web client ID
   (`EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID`), never the Android one; Google matches the Android client
   by package and SHA-1, and without it the native sign-in fails with `DEVELOPER_ERROR`.

### Sessions: tokens in the body or in HttpOnly cookies

Sign-in (`/login`, `/google`) opens a session and answers its `idUserSession` together with a
15-minute access token and a 7-day refresh token. How the client receives the tokens depends on
one header:

| Client | Header | Tokens |
|---|---|---|
| Mobile app | none | In the body. The refresh token goes back in the body of `/refresh`. |
| Web app | `X-Session-Transport: cookie` | In HttpOnly cookies; `accessToken` and `refreshToken` come back `null`. No script on the page can read them, so an XSS cannot steal the session. |

The cookies (`SessionCookies`):

- **`em_access`**: the access token. `Path=/api`, lives as long as the token. The gateway turns it
  into `Authorization: Bearer …` (only when the request also brings
  `X-Requested-With: XMLHttpRequest`), so this service and the others keep validating a bearer
  token.
- **`em_refresh`**: the refresh token. `Path=/api/v1/auth`, so it only travels to the account
  endpoints. `/refresh` reads it when the request has no body and brings the transport header,
  rotates it and sets both cookies again; a rejected one clears them.
- Both are `HttpOnly` and `SameSite=Strict`, and `Secure` unless
  `SECURITY_SESSION_COOKIE_SECURE=false`. Turn that off only where the site is served over plain
  HTTP (the local Docker stack and development mode); in production it stays on.
- `/logout` and `/account/delete` clear them.

The CSRF protection the ambient cookies need: a cross-site request never carries them
(`SameSite=Strict`), and using them also takes a custom header a form or an image cannot send.

`/logout {idUserSession}` closes only a session of the caller: another account's session is
answered `404`, exactly like an unknown one.

## Running behind the API gateway

The clients reach this service through the API gateway (`../en-monitor-api-gateway`, `:8080`),
which forwards `/api/v1/auth/**` and `/api/v1/admin/users|roles/**` here after checking the token
and answering CORS. It drops the `Origin` header, so this service never answers CORS itself, and it
never forwards `/internal/**`.

The application records `request.getRemoteAddr()` as the caller's address; the password-recovery
attempt limiter and the audit trail are keyed on it. Behind the gateway that would be the
gateway's address for everyone, and the recovery limit would become one limit shared by all users.
So `application.yaml` sets `server.forward-headers-strategy: native`, and
`server.tomcat.remoteip.internal-proxies` to loopback and `172.16.0.0/12` only.

Tomcat's `RemoteIpValve` then takes the caller's address from `X-Forwarded-For`, which the gateway
appends, but **only when the connection comes from loopback or a Docker network**. The default list
would also trust 10.x and 192.168.x, and a machine of the LAN could then pass as `127.0.0.1` and
get through the network check of `/internal/**` (it would still need the token). A client that
connects directly from anywhere else is recorded by its own address, whatever header it sends.

## Tests

```bash
SPRING_DATASOURCE_PASSWORD=... ./mvnw test
```

The persistence tests run against the real MySQL of the infra repository, because Liquibase owns
the schema. Every test runs under the `test` profile (test-only pepper, key pair under
`~/.energy-monitor/keys`). The outbox relay is off in that profile, and the messages the suite
writes are stored already discarded, so nothing it does is ever published.

`RabbitOutboxPublisherBrokerTest` runs against a real RabbitMQ when one answers on
`RABBITMQ_HOST:RABBITMQ_PORT` (credentials from `RABBITMQ_USERNAME` and `RABBITMQ_PASSWORD`), and
is skipped otherwise.

## Docker

```bash
docker build -t energy-monitor-security .
```

The infra repository builds the image and runs it next to MySQL, RabbitMQ, energy-monitor-backend
and the API gateway (`infra/docker-compose.yml` on one machine, `infra/docker-compose.prod.yml` on
a server). It listens on 8082 inside the Docker network only, runs as `BACKEND_UID:BACKEND_GID` of
`infra/.env` so it can read `private.pem`, and its container health is `/actuator/health` (database
and broker included).

`.github/workflows/ci-cd.yml` runs the suite against a MySQL of the runner on every pull request
and push to `dev` and `main`, and after a push to `main` (and the approval of the `production`
environment) deploys it with `infra/deploy/deploy.sh security`.

## Working conventions

Git workflow based on `main` / `dev` / `feat` / `fix` / `chore` / `hotfix` branches and
Conventional Commits. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Team

| Team member | Main role | Additional roles |
|---|---|---|
| Juan Esteban Cortes Parra | Project Lead / DB Manager | Backend Developer, API & Cloud Developer, Tester |
| Miguel Ángel García Artunduaga / Juan Esteban Cortez Parra | Developer | Backend Developer, API & Cloud Developer |
| Miguel Ángel García Artunduaga | Analyst | Frontend Developer, Tester / UX-UI Designer |
