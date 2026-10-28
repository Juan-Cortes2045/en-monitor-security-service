package com.energymonitor.security.infrastructure;

import com.energymonitor.security.adapter.out.dns.DnsEmailDomainCheckAdapter;
import com.energymonitor.security.application.port.out.AccountDeletionCodeDeliveryPort;
import com.energymonitor.security.application.exception.AccountDeletionCodeUnavailableException;
import com.energymonitor.security.adapter.out.messaging.OutboxMailDeliveryAdapter;
import com.energymonitor.security.adapter.out.security.InMemoryResetAttemptLimiter;
import com.energymonitor.security.adapter.out.security.PepperedHmacResetCodeHasher;
import com.energymonitor.security.api.AdministratorQuery;
import com.energymonitor.security.api.EmailVerificationDeliveryPort;
import com.energymonitor.security.api.PasswordResetDeliveryPort;
import com.energymonitor.security.api.UserProfileQuery;
import com.energymonitor.security.application.port.in.AdministerUserAccount;
import com.energymonitor.security.application.port.in.AssignRole;
import com.energymonitor.security.application.port.in.AuthenticateUser;
import com.energymonitor.security.application.port.in.ChangePassword;
import com.energymonitor.security.application.port.in.CheckPermission;
import com.energymonitor.security.application.port.in.CreatePasswordResetToken;
import com.energymonitor.security.application.port.in.CreateUserSession;
import com.energymonitor.security.application.port.in.DeleteAccount;
import com.energymonitor.security.application.port.in.EmailVerification;
import com.energymonitor.security.application.port.in.FindUser;
import com.energymonitor.security.application.port.in.ListUserAccounts;
import com.energymonitor.security.application.port.in.LogoutUserSession;
import com.energymonitor.security.application.port.in.ManageUserStatus;
import com.energymonitor.security.application.port.in.RefreshSession;
import com.energymonitor.security.application.port.in.RegisterUser;
import com.energymonitor.security.application.port.in.ResetPassword;
import com.energymonitor.security.application.port.in.RevokeRole;
import com.energymonitor.security.application.port.in.SignInWithGoogle;
import com.energymonitor.security.application.port.in.UpdateUserProfile;
import com.energymonitor.security.application.port.out.AccountDeletionGuardPort;
import com.energymonitor.security.application.port.out.AccountEventPublisherPort;
import com.energymonitor.security.application.port.out.AuditLogPersistencePort;
import com.energymonitor.security.application.port.out.EmailDomainCheckPort;
import com.energymonitor.security.application.usecase.PurgePendingRegistrationsService;
import com.energymonitor.security.application.port.out.PendingRegistrationPersistencePort;
import com.energymonitor.security.application.port.in.PurgePendingRegistrations;
import com.energymonitor.security.application.port.out.IdentifierGeneratorPort;
import com.energymonitor.security.application.port.out.LoginErrorLogPersistencePort;
import com.energymonitor.security.application.port.out.PasswordHasherPort;
import com.energymonitor.security.application.port.out.PasswordPolicyPersistencePort;
import com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort;
import com.energymonitor.security.application.port.out.PasswordResetTokenPersistencePort;
import com.energymonitor.security.application.port.out.PermissionPersistencePort;
import com.energymonitor.security.application.port.out.PersonPersistencePort;
import com.energymonitor.security.application.port.out.ProfileImageFetcherPort;
import com.energymonitor.security.application.port.out.RefreshTokenHasherPort;
import com.energymonitor.security.application.port.out.RefreshTokenPersistencePort;
import com.energymonitor.security.application.port.out.ResetAttemptLimiterPort;
import com.energymonitor.security.application.port.out.SystemRolePermissionPersistencePort;
import com.energymonitor.security.application.port.out.SystemRolePersistencePort;
import com.energymonitor.security.application.port.out.TokenGeneratorPort;
import com.energymonitor.security.application.port.out.UserDirectoryPort;
import com.energymonitor.security.application.port.out.UserPersistencePort;
import com.energymonitor.security.application.port.out.UserSessionPersistencePort;
import com.energymonitor.security.application.port.out.UserSystemRolePersistencePort;
import com.energymonitor.security.application.usecase.AdministerUserAccountService;
import com.energymonitor.security.application.usecase.AdministratorQueryService;
import com.energymonitor.security.application.usecase.AssignRoleService;
import com.energymonitor.security.application.usecase.AuthenticateUserService;
import com.energymonitor.security.application.usecase.ChangePasswordService;
import com.energymonitor.security.application.usecase.CheckPermissionService;
import com.energymonitor.security.application.usecase.CreatePasswordResetTokenService;
import com.energymonitor.security.application.usecase.CreateUserSessionService;
import com.energymonitor.security.application.usecase.DeleteAccountService;
import com.energymonitor.security.application.usecase.EmailVerificationService;
import com.energymonitor.security.application.usecase.FindUserService;
import com.energymonitor.security.application.usecase.ListUserAccountsService;
import com.energymonitor.security.application.usecase.LogoutUserSessionService;
import com.energymonitor.security.application.usecase.ManageUserStatusService;
import com.energymonitor.security.application.usecase.RefreshSessionService;
import com.energymonitor.security.application.usecase.RegisterUserService;
import com.energymonitor.security.application.usecase.ResetPasswordService;
import com.energymonitor.security.application.usecase.RevokeRoleService;
import com.energymonitor.security.application.usecase.SignInWithGoogleService;
import com.energymonitor.security.application.usecase.UpdateUserProfileService;
import com.energymonitor.security.application.usecase.UserProfileQueryService;
import java.time.Clock;
import java.time.Duration;
import org.aopalliance.aop.Advice;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.interceptor.DefaultTransactionAttribute;
import org.springframework.transaction.interceptor.TransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;

/**
 * Wires the Security application layer into the Spring context.
 *
 * <p>This is the only place that knows both halves of the architecture: it instantiates the
 * use cases, which stay plain Java classes with no annotations of their own, from the output
 * ports, which the persistence and security adapters implement as Spring beans.
 *
 * <h2>Transaction boundaries</h2>
 *
 * <p>The boundary is created here, as an explicit proxy around the use case, rather than with
 * {@code @Transactional} on the use case class. Two reasons, and the first one is a trap:
 * annotating the {@code @Bean} factory methods below would be silently inert, because
 * Spring's auto-proxy creator decides whether to wrap a bean by inspecting the <em>target
 * class</em> for {@code @Transactional} and never looks at the factory method that produced
 * it. The result would look configured and commit nothing. The second reason is the one that
 * matters architecturally: the use cases must not import Spring, so the annotation cannot go
 * on them at all.
 *
 * <p>Building the proxy here makes the boundary verifiable instead of assumed.
 * {@code SecurityTransactionBoundaryTest} asserts that each of these beans really is advised
 * by a {@link TransactionInterceptor} and that the single-write and read-only flows really are
 * not, so a later refactor cannot quietly move or drop one.
 *
 * <p>Multi-write flows get the boundary because a partial commit would leave inconsistent
 * state:
 *
 * <ul>
 *   <li>{@link RegisterUserService} - person, account and audit row.</li>
 *   <li>{@link UpdateUserProfileService} - person, optional account, audit row.</li>
 *   <li>{@link AuthenticateUserService} - the account's failure counter together with its
 *       audit or typed-error row. Partial failure here would either erase a failed-attempt
 *       record or reset the counter without a matching login.</li>
 *   <li>{@link ChangePasswordService} - new hash and the audit trail of the change.</li>
 *   <li>{@link ResetPasswordService} - new hash, token consumption and audit row. Partial
 *       failure would leave the password changed but the token still reusable.</li>
 *   <li>{@link LogoutUserSessionService} - session closure and its logout audit row.</li>
 *   <li>{@link AssignRoleService} / {@link RevokeRoleService} - assignment and audit row.</li>
 *   <li>{@link ManageUserStatusService} - account state and audit row.</li>
 *   <li>{@link AdministerUserAccountService} - an administrator's change to another account,
 *       together with the sessions it revokes.</li>
 * </ul>
 *
 * <p>{@link CreateUserSessionService}, {@link CreatePasswordResetTokenService},
 * {@link FindUserService}, {@link CheckPermissionService} and
 * {@link ListUserAccountsService} are read-only or write a single
 * row, so a transaction would add nothing but an extra connection and are deliberately left
 * without a boundary.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(SecurityResetProperties.class)
public class SecurityApplicationWiring {

    /**
     * The clock every use case receives, so time is a constructor dependency rather than a
     * static call and tests can pin it.
     *
     * @return a UTC clock
     */
    @Bean
    public Clock securityClock() {
        return Clock.systemUTC();
    }

    /**
     * The digest used for password-recovery codes, peppered rather than plain.
     *
     * <p>Built here rather than component-scanned because it needs the configured pepper, which
     * is a value and not a type Spring can inject. The adapter refuses a missing or short pepper,
     * so a deployment that forgot it fails at startup instead of storing recovery codes that a
     * database dump could reverse in seconds.
     *
     * @param properties the bound {@code security.reset.*} settings
     * @return the hasher for recovery codes
     */
    @Bean
    public PasswordResetTokenHasherPort passwordResetTokenHasher(SecurityResetProperties properties) {
        return new PepperedHmacResetCodeHasher(properties.pepper());
    }

    /**
     * How often one caller address may attempt to redeem a recovery code.
     *
     * <p>The counter lives in memory, which means it is per instance and does not survive a
     * restart. Both limits are the safe direction to fail: the cost is a fresh allowance rather
     * than an account that cannot be recovered.
     *
     * @param properties the bound {@code security.reset.*} settings
     * @param clock      time source the windows are measured against
     * @return the limiter
     */
    @Bean
    public ResetAttemptLimiterPort resetAttemptLimiter(SecurityResetProperties properties,
                                                      Clock clock) {
        return new InMemoryResetAttemptLimiter(
                properties.maxAttemptsPerWindow(), properties.attemptWindow(), clock);
    }

    /**
     * Wraps a use case in a proxy that runs it inside a transaction.
     *
     * <p>The proxy implements only the input port, so callers depend on the interface and the
     * application layer stays unaware that a proxy sits between it and the Spring context.
     * Rollback is the default: any {@link RuntimeException} the use case raises, including
     * every typed application failure, leaves the database untouched.
     *
     * @param <T>          the input port type
     * @param transactions  the transaction manager
     * @param target        the use case to protect
     * @param inputPort     the interface callers inject
     * @return the transactional proxy
     */
    private <T> T transactional(PlatformTransactionManager transactions, T target,
                                Class<T> inputPort) {
        TransactionAttributeSource everyMethod = new TransactionAttributeSource() {
            @Override
            public org.springframework.transaction.interceptor.TransactionAttribute
            getTransactionAttribute(java.lang.reflect.Method method, Class<?> targetClass) {
                return new DefaultTransactionAttribute();
            }
        };
        Advice transactionAdvice = new TransactionInterceptor(transactions, everyMethod);
        ProxyFactory proxyFactory = new ProxyFactory(target);
        proxyFactory.setInterfaces(inputPort);
        proxyFactory.addAdvice(transactionAdvice);
        return inputPort.cast(proxyFactory.getProxy());
    }

    /**
     * The mail-domain check of registration. {@code security.email-domain-check.enabled=false}
     * turns it off (the test profile does, so the suite never depends on the network).
     */
    @Bean
    public EmailDomainCheckPort emailDomainCheck(
            @Value("${security.email-domain-check.enabled:true}") boolean enabled) {
        return enabled ? DnsEmailDomainCheckAdapter.usingSystemResolver(Duration.ofSeconds(3))
                : domain -> true;
    }

    @Bean
    public RegisterUser registerUser(UserPersistencePort users,
                                     PendingRegistrationPersistencePort registrations,
                                     PasswordPolicyPersistencePort policies,
                                     PasswordHasherPort hasher, IdentifierGeneratorPort identifiers,
                                     EmailDomainCheckPort emailDomains, Clock clock,
                                     PlatformTransactionManager transactions) {
        return transactional(transactions,
                new RegisterUserService(users, registrations, policies, hasher, identifiers,
                        emailDomains, clock),
                RegisterUser.class);
    }

    @Bean
    public PurgePendingRegistrations purgePendingRegistrations(
            PendingRegistrationPersistencePort registrations, Clock clock,
            PlatformTransactionManager transactions) {
        return transactional(transactions,
                new PurgePendingRegistrationsService(registrations, clock),
                PurgePendingRegistrations.class);
    }

    @Bean
    public SignInWithGoogle signInWithGoogle(UserPersistencePort users, PersonPersistencePort persons,
                                             PasswordHasherPort hasher, TokenGeneratorPort tokens,
                                             ProfileImageFetcherPort images,
                                             IdentifierGeneratorPort identifiers,
                                             AuditLogPersistencePort audits,
                                             AccountEventPublisherPort events, Clock clock,
                                             PlatformTransactionManager transactions) {
        return transactional(transactions,
                new SignInWithGoogleService(users, persons, hasher, tokens, images, identifiers, audits,
                        events, clock),
                SignInWithGoogle.class);
    }

    @Bean
    public AuthenticateUser authenticateUser(UserPersistencePort users,
                                             PendingRegistrationPersistencePort registrations,
                                             PasswordHasherPort hasher,
                                             IdentifierGeneratorPort identifiers,
                                             AuditLogPersistencePort audits,
                                             LoginErrorLogPersistencePort loginErrorLog,
                                             AccountEventPublisherPort events, Clock clock,
                                             PlatformTransactionManager transactions) {
        return transactional(transactions,
                new AuthenticateUserService(users, registrations, hasher, identifiers, audits,
                        loginErrorLog, events, clock),
                AuthenticateUser.class);
    }

    @Bean
    public UpdateUserProfile updateUserProfile(UserPersistencePort users,
                                               PersonPersistencePort persons,
                                               AuditLogPersistencePort audits,
                                               IdentifierGeneratorPort identifiers,
                                               EmailDomainCheckPort emailDomains, Clock clock,
                                               PlatformTransactionManager transactions) {
        return transactional(transactions,
                new UpdateUserProfileService(users, persons, audits, identifiers, emailDomains,
                        clock),
                UpdateUserProfile.class);
    }

    @Bean
    public ManageUserStatus manageUserStatus(UserPersistencePort users,
                                             AuditLogPersistencePort audits,
                                             IdentifierGeneratorPort identifiers, Clock clock,
                                             PlatformTransactionManager transactions) {
        return transactional(transactions,
                new ManageUserStatusService(users, audits, identifiers, clock),
                ManageUserStatus.class);
    }

    @Bean
    public ChangePassword changePassword(UserPersistencePort users, PasswordHasherPort hasher,
                                         PasswordPolicyPersistencePort policies,
                                         AuditLogPersistencePort audits,
                                         IdentifierGeneratorPort identifiers, Clock clock,
                                         PlatformTransactionManager transactions) {
        return transactional(transactions,
                new ChangePasswordService(users, hasher, policies, audits, identifiers, clock),
                ChangePassword.class);
    }

    @Bean
    public ResetPassword resetPassword(UserPersistencePort users,
                                       PasswordResetTokenPersistencePort tokens,
                                       PasswordResetTokenHasherPort tokenHasher,
                                       PasswordHasherPort hasher,
                                       PasswordPolicyPersistencePort policies,
                                       AuditLogPersistencePort audits,
                                       IdentifierGeneratorPort identifiers, Clock clock,
                                       PlatformTransactionManager transactions) {
        return transactional(transactions,
                new ResetPasswordService(users, tokens, tokenHasher, hasher, policies, audits,
                        identifiers, clock),
                ResetPassword.class);
    }

    /**
     * Issues a recovery code inside a transaction, so that the message can wait for the commit.
     *
     * <p>This used to be deliberately outside any boundary, on the reasoning that a transaction
     * cannot roll back a message that already left the process, so wrapping the pair would promise
     * an atomicity that does not exist. That reasoning was right while the send happened inside the
     * call and is wrong now that it does not.
     *
     * <p>Delivery is queued and dispatched as an after-commit callback, so the boundary is what
     * makes the ordering honest: the row carrying the code is durable before anything is sent, and a
     * rollback sends nothing at all. Without the transaction the callback has no commit to wait for,
     * and the message would be built against a row that a later failure could still remove.
     *
     * @param users          account storage
     * @param tokens         reset token storage
     * @param tokenGenerator token generation port
     * @param tokenHasher    digest of the generated and presented secrets
     * @param delivery       the channel the clear secret leaves through
     * @param identifiers    identifier port
     * @param clock          time source
     * @param transactions   the transaction manager
     * @return the use case
     */
    @Bean
    public CreatePasswordResetToken createPasswordResetToken(
            UserPersistencePort users, PasswordResetTokenPersistencePort tokens,
            TokenGeneratorPort tokenGenerator, PasswordResetTokenHasherPort tokenHasher,
            PasswordResetDeliveryPort delivery, IdentifierGeneratorPort identifiers, Clock clock,
            PlatformTransactionManager transactions) {
        return transactional(transactions,
                new CreatePasswordResetTokenService(users, tokens, tokenGenerator, tokenHasher,
                        delivery, identifiers, clock),
                CreatePasswordResetToken.class);
    }

    /**
     * Writes a single session row, so no transaction boundary is needed.
     *
     * @param users          account storage
     * @param sessions       session storage
     * @param tokenGenerator token generation port
     * @param identifiers    identifier port
     * @param clock          time source
     * @return the use case
     */
    /**
     * The per-address limiter is built here rather than exposed as a bean: a second
     * {@link ResetAttemptLimiterPort} bean would make every by-type injection of the per-caller
     * one ambiguous. Five guesses per address per window keep a six-digit code out of reach.
     */
    @Bean
    public EmailVerification emailVerification(UserPersistencePort users,
                                               PendingRegistrationPersistencePort registrations,
                                               PersonPersistencePort persons,
                                               AuditLogPersistencePort audits,
                                               AccountEventPublisherPort events,
                                               IdentifierGeneratorPort identifiers,
                                               PasswordResetTokenHasherPort tokenHasher,
                                               EmailVerificationDeliveryPort delivery, Clock clock,
                                               PlatformTransactionManager transactions) {
        return transactional(transactions,
                new EmailVerificationService(users, registrations, persons, audits, events,
                        identifiers, tokenHasher, delivery,
                        new InMemoryResetAttemptLimiter(5, Duration.ofMinutes(15), clock), clock),
                EmailVerification.class);
    }

    /** Read-only, so no transaction: each lookup is a single statement. */
    @Bean
    public UserProfileQuery userProfileQuery(UserPersistencePort users,
                                             PersonPersistencePort persons) {
        return new UserProfileQueryService(users, persons);
    }

    /**
     * Transactional on purpose: the deletion and its AccountDeleted message in the outbox commit
     * together, so the other services hear about every deletion and only about real ones.
     */
    @Bean
    public DeleteAccount deleteAccount(UserPersistencePort users, PersonPersistencePort persons,
                                       UserSessionPersistencePort sessions,
                                       PasswordHasherPort hasher, AuditLogPersistencePort audits,
                                       AccountEventPublisherPort events,
                                       AccountDeletionGuardPort deletionGuard,
                                       IdentifierGeneratorPort identifiers,
                                       PasswordResetTokenHasherPort codeHasher,
                                       AccountDeletionCodeDeliveryPort codeDelivery, Clock clock,
                                       PlatformTransactionManager transactions) {
        // Five guesses per account per window, like the verification code: a six-digit code is
        // only safe while guessing is bounded.
        return transactional(transactions,
                new DeleteAccountService(users, persons, sessions, hasher, audits, events,
                        deletionGuard, identifiers, codeHasher, codeDelivery,
                        new InMemoryResetAttemptLimiter(5, Duration.ofMinutes(15), clock), clock),
                DeleteAccount.class);
    }

    /**
     * Where the deletion code of an account created with Google goes. Off by default: the
     * notification service does not deliver {@code mail.account-deletion} yet, and a message no
     * queue takes stays first in the outbox and holds back every mail behind it. Until
     * {@code security.account-deletion.code-mail-enabled=true}, asking for the code answers 503
     * and nothing is written.
     */
    @Bean
    public AccountDeletionCodeDeliveryPort accountDeletionCodeDelivery(
            @Value("${security.account-deletion.code-mail-enabled:false}") boolean enabled,
            OutboxMailDeliveryAdapter mail) {
        if (enabled) {
            return mail::deliverAccountDeletionCode;
        }
        return (userId, recipient, code, validUntil) -> {
            throw new AccountDeletionCodeUnavailableException(
                    "The deletion code cannot be mailed yet.");
        };
    }

    @Bean
    public CreateUserSession createUserSession(UserPersistencePort users,
                                               UserSessionPersistencePort sessions,
                                               IdentifierGeneratorPort identifiers, Clock clock) {
        return new CreateUserSessionService(users, sessions, identifiers, clock);
    }

    /**
     * Rotates a refresh token. Transactional because a rotation writes the retired generation,
     * its replacement and the session slide together, and a partial application would either
     * retire a token without handing out its successor or leave two active generations in one
     * family.
     *
     * @param tokens   refresh token storage
     * @param sessions session storage
     * @param users    account storage, the source of the identity the new access token is
     *                minted from
     * @param hasher   digest of the presented and issued secrets
     * @param secrets  secure secret generation
     * @param audits   audit trail port
     * @param identifiers identifier port
     * @param clock    time source
     * @return the use case behind a transaction proxy
     */
    @Bean
    public RefreshSession refreshSession(RefreshTokenPersistencePort tokens,
                                         UserSessionPersistencePort sessions,
                                         UserPersistencePort users,
                                         RefreshTokenHasherPort hasher, TokenGeneratorPort secrets,
                                         AuditLogPersistencePort audits,
                                         IdentifierGeneratorPort identifiers, Clock clock,
                                         PlatformTransactionManager transactions) {
        return transactional(transactions,
                new RefreshSessionService(tokens, sessions, users, hasher, secrets, audits,
                        identifiers, clock),
                RefreshSession.class);
    }

    @Bean
    public LogoutUserSession logoutUserSession(UserSessionPersistencePort sessions,
                                               AuditLogPersistencePort audits,
                                               IdentifierGeneratorPort identifiers, Clock clock,
                                               PlatformTransactionManager transactions) {
        return transactional(transactions,
                new LogoutUserSessionService(sessions, audits, identifiers, clock),
                LogoutUserSession.class);
    }

    @Bean
    public AssignRole assignRole(UserPersistencePort users, SystemRolePersistencePort roles,
                                 UserSystemRolePersistencePort assignments,
                                 AuditLogPersistencePort audits, IdentifierGeneratorPort identifiers,
                                 Clock clock, PlatformTransactionManager transactions) {
        return transactional(transactions,
                new AssignRoleService(users, roles, assignments, audits, identifiers, clock),
                AssignRole.class);
    }

    @Bean
    public RevokeRole revokeRole(UserSystemRolePersistencePort assignments,
                                 AuditLogPersistencePort audits,
                                 IdentifierGeneratorPort identifiers, Clock clock,
                                 PlatformTransactionManager transactions) {
        return transactional(transactions,
                new RevokeRoleService(assignments, audits, identifiers, clock),
                RevokeRole.class);
    }

    @Bean
    public FindUser findUser(UserPersistencePort users) {
        return new FindUserService(users);
    }

    @Bean
    public CheckPermission checkPermission(UserPersistencePort users,
                                           PermissionPersistencePort permissions,
                                           SystemRolePersistencePort roles,
                                           UserSystemRolePersistencePort assignments,
                                           SystemRolePermissionPersistencePort grants) {
        return new CheckPermissionService(users, permissions, roles, assignments, grants);
    }

    @Bean
    public ListUserAccounts listUserAccounts(UserDirectoryPort directory,
                                             UserSystemRolePersistencePort assignments,
                                             SystemRolePersistencePort roles) {
        return new ListUserAccountsService(directory, assignments, roles);
    }

    @Bean
    public AdministerUserAccount administerUserAccount(UserPersistencePort users,
                                                       SystemRolePersistencePort roles,
                                                       UserSystemRolePersistencePort assignments,
                                                       UserSessionPersistencePort sessions,
                                                       ManageUserStatus manageUserStatus,
                                                       AssignRole assignRole, RevokeRole revokeRole,
                                                       AccountEventPublisherPort events,
                                                       Clock clock,
                                                       PlatformTransactionManager transactions) {
        return transactional(transactions,
                new AdministerUserAccountService(users, roles, assignments, sessions,
                        manageUserStatus, assignRole, revokeRole, events, clock),
                AdministerUserAccount.class);
    }

    @Bean
    public AdministratorQuery administratorQuery(SystemRolePersistencePort roles,
                                                 UserSystemRolePersistencePort assignments,
                                                 UserPersistencePort users) {
        return new AdministratorQueryService(roles, assignments, users);
    }
}
