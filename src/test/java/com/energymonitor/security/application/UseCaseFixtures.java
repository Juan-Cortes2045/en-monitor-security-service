package com.energymonitor.security.application;

import com.energymonitor.security.api.AccountAdministered;
import com.energymonitor.security.api.AccountDeleted;
import com.energymonitor.security.api.AccountFirstSignedIn;
import com.energymonitor.security.api.AccountRegistered;
import com.energymonitor.security.api.PasswordResetDeliveryPort;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.LoginErrorLogPersistencePort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenPersistencePort;
import com.energymonitor.security.application.port.out.PermissionPersistencePort;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import com.energymonitor.security.application.port.out.SystemRolePermissionPersistencePort;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.domain.model.AuditLog;
import com.energymonitor.security.domain.model.Email;
import com.energymonitor.security.domain.model.LoginErrorLog;
import com.energymonitor.security.domain.model.PasswordHash;
import com.energymonitor.security.domain.model.PasswordPolicy;
import com.energymonitor.security.domain.model.PasswordResetToken;
import com.energymonitor.security.domain.model.Permission;
import com.energymonitor.security.domain.model.PendingRegistration;
import com.energymonitor.security.domain.model.Person;
import com.energymonitor.security.domain.model.SystemRole;
import com.energymonitor.security.domain.model.SystemRolePermission;
import com.energymonitor.security.domain.model.User;
import com.energymonitor.security.domain.model.UserSession;
import com.energymonitor.security.domain.model.UserStatus;
import com.energymonitor.security.domain.model.UserSystemRole;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * In-memory fakes of the output ports, for application-layer tests only.
 *
 * <p>They replace the {@code @Component} persistence adapters so the use cases can be
 * exercised without a database. The hasher fake is deliberately naive: {@code hash(raw)} is
 * {@code "hash:" + raw}, which is enough for the application to verify that hashes are
 * produced and compared through the port and never break domain rules.
 */
public final class UseCaseFixtures {

    public static final String PASSWORD = "StrongPass1!";
    public static final Instant REGISTRATION = Instant.parse("2026-01-02T03:04:05Z");

    private UseCaseFixtures() {
    }

    /** Seeds a default password policy: min 8, requires upper case, digits and symbols. */
    public static PasswordPolicy defaultPolicy() {
        return new PasswordPolicy("pol0000001", 8, 64, true, true, true, 90);
    }

    public static final class FakeUserPersistencePort implements UserPersistencePort {

        private final Map<String, User> byId = new LinkedHashMap<>();

        @Override
        public User save(User user) {
            byId.put(user.idUser(), user);
            return user;
        }

        @Override
        public Optional<User> findActive(String idUser) {
            return Optional.ofNullable(byId.get(idUser));
        }

        @Override
        public Optional<User> findActiveByEmail(Email email) {
            return byId.values().stream()
                    .filter(user -> user.email().equals(email))
                    .findFirst();
        }

        @Override
        public Optional<User> findActiveByGoogleSubject(String googleSubject) {
            return byId.values().stream()
                    .filter(user -> user.googleSubject().filter(googleSubject::equals).isPresent())
                    .findFirst();
        }

        @Override
        public void softDelete(String idUser, Instant deletedAt) {
            byId.remove(idUser);
        }

        public User seed(String idUser, String idPerson, String email, UserStatus status) {
            User user = new User(idUser, idPerson, PasswordHash.of("hash:" + PASSWORD),
                    Email.of(email), true, REGISTRATION, status, 0, null, null);
            user.acceptTerms(REGISTRATION);
            byId.put(idUser, user);
            return user;
        }

        public List<User> users() {
            return new ArrayList<>(byId.values());
        }
    }

    public static final class FakePendingRegistrationPersistencePort
            implements PendingRegistrationPersistencePort {

        private final Map<String, PendingRegistration> byEmail = new LinkedHashMap<>();

        @Override
        public PendingRegistration save(PendingRegistration registration) {
            byEmail.put(registration.email().value(), registration);
            return registration;
        }

        @Override
        public Optional<PendingRegistration> findByEmail(Email email) {
            return Optional.ofNullable(byEmail.get(email.value()));
        }

        @Override
        public void delete(String idUser) {
            byEmail.values().removeIf(registration -> registration.idUser().equals(idUser));
        }

        @Override
        public int deleteExpired(Instant instant) {
            int before = byEmail.size();
            byEmail.values().removeIf(registration -> registration.isExpiredAt(instant));
            return before - byEmail.size();
        }

        public List<PendingRegistration> registrations() {
            return new ArrayList<>(byEmail.values());
        }
    }

    public static final class FakePersonPersistencePort implements PersonPersistencePort {

        private final Map<String, Person> byId = new LinkedHashMap<>();

        /**
         * Snapshots of every person handed to {@link #save}, kept because reading the map back is
         * not enough on its own: the fake stores the very instance the use case mutated, so a
         * read-back would show a rename that was never written. Only a use case that actually
         * called the port leaves an entry here.
         */
        private final List<Person> saved = new ArrayList<>();

        @Override
        public Person save(Person person) {
            byId.put(person.idPerson(), person);
            saved.add(new Person(person.idPerson(), person.name(), person.lastName()));
            return person;
        }

        @Override
        public Optional<Person> findActive(String idPerson) {
            return Optional.ofNullable(byId.get(idPerson));
        }

        @Override
        public void softDelete(String idPerson, Instant deletedAt) {
            byId.remove(idPerson);
        }

        public Person seed(String idPerson) {
            Person person = new Person(idPerson, "Ada", "Lovelace");
            byId.put(idPerson, person);
            return person;
        }

        /** @return the name and last name of each saved person, in call order */
        public List<String> savedNames() {
            return saved.stream().map(person -> person.name() + " " + person.lastName()).toList();
        }
    }

    public static final class FakePasswordHasherPort implements PasswordHasherPort {

        private static final String PREFIX = "hash:";

        @Override
        public PasswordHash hash(String rawPassword) {
            return PasswordHash.of(PREFIX + rawPassword);
        }

        @Override
        public boolean matches(String rawPassword, PasswordHash passwordHash) {
            return passwordHash.value().equals(PREFIX + rawPassword);
        }
    }

    public static final class FakeIdentifierGeneratorPort implements IdentifierGeneratorPort {

        private int sequence;

        @Override
        public String generate() {
            sequence++;
            return "id" + String.format("%07d", sequence);
        }
    }

    public static final class FakeTokenGeneratorPort implements TokenGeneratorPort {

        private int sequence;

        @Override
        public String generateToken() {
            sequence++;
            return "token-" + sequence;
        }

        /**
         * A recognisable six-digit code rather than a random one, so a test can assert on the value
         * it was handed without having to read it back out of a fixture.
         */
        @Override
        public String generateNumericCode(int digits) {
            sequence++;
            return String.format("%0" + digits + "d", 100000 + sequence);
        }
    }

    public static final class FakePasswordPolicyPersistencePort implements PasswordPolicyPersistencePort {

        private PasswordPolicy policy = defaultPolicy();

        @Override
        public PasswordPolicy save(PasswordPolicy policy) {
            this.policy = policy;
            return policy;
        }

        @Override
        public Optional<PasswordPolicy> findActive(String idPasswordPolicy) {
            return policy.idPasswordPolicy().equals(idPasswordPolicy) ? Optional.of(policy) : Optional.empty();
        }

        @Override
        public List<PasswordPolicy> findAllActive() {
            return List.of(policy);
        }

        public FakePasswordPolicyPersistencePort configure(PasswordPolicy policy) {
            this.policy = policy;
            return this;
        }
    }

    public static final class FakeAuditLogPersistencePort implements AuditLogPersistencePort {

        private final List<AuditLog> logs = new ArrayList<>();

        @Override
        public AuditLog save(AuditLog log) {
            logs.add(log);
            return log;
        }

        @Override
        public Optional<AuditLog> findActive(String idAuditLog) {
            return logs.stream()
                    .filter(log -> log.idAuditLog().equals(idAuditLog))
                    .findFirst();
        }

        public List<AuditLog> logs() {
            return logs;
        }
    }

    public static final class FakeLoginErrorLogPersistencePort implements LoginErrorLogPersistencePort {

        private final List<LoginErrorLog> errors = new ArrayList<>();

        @Override
        public LoginErrorLog save(LoginErrorLog log) {
            errors.add(log);
            return log;
        }

        @Override
        public Optional<LoginErrorLog> findActive(String idLoginError) {
            return errors.stream()
                    .filter(log -> log.idLoginError().equals(idLoginError))
                    .findFirst();
        }

        @Override
        public List<LoginErrorLog> listNewestFirst() {
            return new ArrayList<>(errors);
        }

        public List<LoginErrorLog> errors() {
            return errors;
        }
    }

    public static final class FakeUserSessionPersistencePort implements UserSessionPersistencePort {

        private final Map<String, UserSession> byId = new LinkedHashMap<>();

        @Override
        public UserSession save(UserSession session) {
            byId.put(session.idUserSession(), session);
            return session;
        }

        @Override
        public Optional<UserSession> findActive(String idUserSession) {
            return Optional.ofNullable(byId.get(idUserSession));
        }

        @Override
        public List<UserSession> listActiveByUser(String idUser) {
            return byId.values().stream()
                    .filter(session -> session.idUser().equals(idUser))
                    .toList();
        }
    }

    /**
     * Keeps tokens in a map keyed by hash, exactly as the real store resolves them, so a test
     * that passes here would pass against MySQL for the same reason.
     *
     * <p>The clear secret is not a key and there is no finder that takes one: the only way into
     * this fake is a hash, which is what makes a use case that forgets to hash before looking
     * up fail here instead of quietly working.
     */
    public static final class FakePasswordResetTokenPersistencePort
            implements PasswordResetTokenPersistencePort {

        private final Map<String, PasswordResetToken> byHash = new LinkedHashMap<>();

        @Override
        public PasswordResetToken save(PasswordResetToken token) {
            byHash.put(token.resetTokenHash(), token);
            return token;
        }

        @Override
        public PasswordResetToken update(PasswordResetToken token) {
            return save(token);
        }

        @Override
        public Optional<PasswordResetToken> findActive(String idResetToken) {
            return byHash.values().stream()
                    .filter(token -> token.idResetToken().equals(idResetToken))
                    .findFirst();
        }

        @Override
        public Optional<PasswordResetToken> findActiveByHash(String resetTokenHash) {
            return Optional.ofNullable(byHash.get(resetTokenHash));
        }

        @Override
        public List<PasswordResetToken> listActiveByUser(String idUser) {
            return byHash.values().stream()
                    .filter(token -> token.idUser().equals(idUser))
                    .toList();
        }

        /** Codes this fake refuses to reserve against, standing in for exhausted or spent ones. */
        private final Set<String> exhausted = new LinkedHashSet<>();

        /**
         * Counts the reservations, so a test can assert that a code was compared at most once per
         * attempt spent rather than once per request received.
         */
        private int reservations;

        /**
         * Stands in for the atomic reservation: refuses when the code is unknown, already used,
         * or listed as exhausted, and otherwise counts it.
         */
        @Override
        public boolean reserveAttempt(String idResetToken) {
            PasswordResetToken token = findActive(idResetToken).orElse(null);
            if (token == null || token.isUsed() || exhausted.contains(idResetToken)) {
                return false;
            }
            reservations++;
            return true;
        }

        /** Marks a code exhausted so the next reservation against it is refused. */
        public FakePasswordResetTokenPersistencePort exhaust(String idResetToken) {
            exhausted.add(idResetToken);
            return this;
        }

        /** @return how many reservations were granted */
        public int reservations() {
            return reservations;
        }

        /**
         * A code is consumed once; a second request asking for the same redemption is told it lost,
         * which is what the conditional update does under concurrency.
         */
        @Override
        public boolean markUsedIfPending(String idResetToken) {
            PasswordResetToken token = findActive(idResetToken).orElse(null);
            if (token == null || token.isUsed()) {
                return false;
            }
            token.markUsed();
            return true;
        }

        /**
         * Consumes every token the user still holds, mirroring what the adapter does before it
         * issues a replacement.
         */
        @Override
        public int consumeAllForUser(String idUser) {
            int consumed = 0;
            for (PasswordResetToken token : byHash.values()) {
                if (token.idUser().equals(idUser) && !token.isUsed()) {
                    token.markUsed();
                    consumed++;
                }
            }
            return consumed;
        }

        /** Stores a token as if it had been read back from the database: no clear secret. */
        public FakePasswordResetTokenPersistencePort store(PasswordResetToken token) {
            byHash.put(token.resetTokenHash(), token);
            return this;
        }
    }

    /**
     * Stands in for the SHA-256 adapter with a reversible prefix, so a test can say which
     * stored hash a secret resolves to without reproducing a digest in test code.
     */
    public static final class FakePasswordResetTokenHasherPort
            implements PasswordResetTokenHasherPort {

        private static final String PREFIX = "hash:";

        /**
         * Reversible and prefixed with the account, so a test can assert which stored value a code
         * resolves to and can see, by reading the string, that two accounts' identical codes do not
         * produce the same digest.
         */
        @Override
        public String hash(String idUser, String clearCode) {
            if (idUser == null || idUser.isBlank()) {
                throw new IllegalArgumentException("idUser must not be null or blank");
            }
            if (clearCode == null || clearCode.isBlank()) {
                throw new IllegalArgumentException("clearCode must not be null or blank");
            }
            return PREFIX + idUser + ":" + clearCode;
        }
    }

    /**
     * Counts attempts instead of enforcing a limit, so a use-case test can assert that an attempt
     * was charged without having to place the clock. A test about the limit itself builds the real
     * {@code InMemoryResetAttemptLimiter}, which is where the arithmetic lives.
     */
    public static final class FakeResetAttemptLimiterPort implements ResetAttemptLimiterPort {

        private int attempts;

        @Override
        public void checkAllowed(String clientIp) {
            attempts++;
        }

        /** @return how many redemption attempts have been charged so far */
        public int attempts() {
            return attempts;
        }
    }

    /**
     * Records what would have been sent, and can be told to fail the way a transport would.
     */
    public static final class FakePasswordResetDeliveryPort
            implements PasswordResetDeliveryPort {

        private final List<Delivery> deliveries = new ArrayList<>();

        /** When set, {@link #deliver} throws it, to simulate an undeliverable channel. */
        private RuntimeException failOnDeliver;

        @Override
        public void deliver(String userId, String recipient, String idResetToken, String clearToken,
                Instant validUntil) {
            if (failOnDeliver != null) {
                throw failOnDeliver;
            }
            deliveries.add(new Delivery(userId, recipient, idResetToken, clearToken, validUntil));
        }

        public void failWith(RuntimeException failure) {
            this.failOnDeliver = failure;
        }

        public List<Delivery> deliveries() {
            return deliveries;
        }

        /** One recorded delivery. */
        /**
         * What was handed to the channel, including the two references the port now carries so the
         * channel can record where the message came from.
         */
        public record Delivery(String userId, String recipient, String idResetToken,
                               String clearToken, Instant validUntil) {
        }
    }

    public static final class FakeSystemRolePersistencePort implements SystemRolePersistencePort {

        private final Map<String, SystemRole> byId = new LinkedHashMap<>();

        @Override
        public SystemRole save(SystemRole role) {
            byId.put(role.idSystemRole(), role);
            return role;
        }

        @Override
        public Optional<SystemRole> findActive(String idSystemRole) {
            return Optional.ofNullable(byId.get(idSystemRole));
        }

        @Override
        public Optional<SystemRole> findActiveByName(String name) {
            return byId.values().stream()
                    .filter(role -> role.name().equals(name))
                    .findFirst();
        }

        @Override
        public List<SystemRole> findAllActive() {
            return new ArrayList<>(byId.values());
        }

        public SystemRole seed(String idSystemRole, String name, boolean enabled) {
            SystemRole role = new SystemRole(idSystemRole, name, null, enabled);
            byId.put(idSystemRole, role);
            return role;
        }
    }

    public static final class FakePermissionPersistencePort implements PermissionPersistencePort {

        private final Map<String, Permission> byId = new LinkedHashMap<>();

        @Override
        public Permission save(Permission permission) {
            byId.put(permission.idPermission(), permission);
            return permission;
        }

        @Override
        public Optional<Permission> findActive(String idPermission) {
            return Optional.ofNullable(byId.get(idPermission));
        }

        @Override
        public Optional<Permission> findActiveByCode(String code) {
            return byId.values().stream()
                    .filter(permission -> permission.code().equals(code))
                    .findFirst();
        }

        @Override
        public List<Permission> findAllActive() {
            return new ArrayList<>(byId.values());
        }

        public Permission seed(String idPermission, String code) {
            Permission permission = new Permission(idPermission, code, code, null);
            byId.put(idPermission, permission);
            return permission;
        }
    }

    public static final class FakeUserSystemRolePersistencePort implements UserSystemRolePersistencePort {

        private final List<UserSystemRole> assignments = new ArrayList<>();

        @Override
        public UserSystemRole save(UserSystemRole assignment) {
            assignments.removeIf(existing ->
                    existing.links(assignment.idUser(), assignment.idSystemRole()));
            assignments.add(assignment);
            return assignment;
        }

        @Override
        public void remove(String idUser, String idSystemRole) {
            assignments.removeIf(existing -> existing.links(idUser, idSystemRole));
        }

        @Override
        public Optional<UserSystemRole> findActive(String idUser, String idSystemRole) {
            return assignments.stream()
                    .filter(existing -> existing.links(idUser, idSystemRole))
                    .findFirst();
        }

        @Override
        public List<UserSystemRole> listActiveByUser(String idUser) {
            return assignments.stream()
                    .filter(assignment -> assignment.idUser().equals(idUser))
                    .toList();
        }

        @Override
        public List<UserSystemRole> listActiveBySystemRole(String idSystemRole) {
            return assignments.stream()
                    .filter(assignment -> assignment.idSystemRole().equals(idSystemRole))
                    .toList();
        }
    }

    public static final class FakeSystemRolePermissionPersistencePort
            implements SystemRolePermissionPersistencePort {

        private final List<SystemRolePermission> grants = new ArrayList<>();

        @Override
        public SystemRolePermission save(SystemRolePermission grant) {
            grants.removeIf(existing -> existing.links(grant.idSystemRole(), grant.idPermission()));
            grants.add(grant);
            return grant;
        }

        @Override
        public void remove(String idSystemRole, String idPermission) {
            grants.removeIf(existing -> existing.links(idSystemRole, idPermission));
        }

        @Override
        public Optional<SystemRolePermission> findActive(String idSystemRole, String idPermission) {
            return grants.stream()
                    .filter(existing -> existing.links(idSystemRole, idPermission))
                    .findFirst();
        }

        @Override
        public List<SystemRolePermission> listActiveBySystemRole(String idSystemRole) {
            return grants.stream()
                    .filter(grant -> grant.idSystemRole().equals(idSystemRole))
                    .toList();
        }

        @Override
        public List<SystemRolePermission> listActiveByPermission(String idPermission) {
            return grants.stream()
                    .filter(grant -> grant.idPermission().equals(idPermission))
                    .toList();
        }
    }

    /** Keeps every published account event, in order. */
    public static final class FakeAccountEventPublisherPort implements AccountEventPublisherPort {

        private final List<Object> events = new ArrayList<>();

        @Override
        public void accountDeleted(AccountDeleted event) {
            events.add(event);
        }

        @Override
        public void accountRegistered(AccountRegistered event) {
            events.add(event);
        }

        @Override
        public void accountAdministered(AccountAdministered event) {
            events.add(event);
        }

        @Override
        public void accountFirstSignedIn(AccountFirstSignedIn event) {
            events.add(event);
        }

        public List<Object> events() {
            return List.copyOf(events);
        }

        public <T> List<T> eventsOf(Class<T> type) {
            return events.stream().filter(type::isInstance).map(type::cast).toList();
        }
    }
}
