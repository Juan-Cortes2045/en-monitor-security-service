package com.energymonitor.security.adapter.out.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.energymonitor.security.domain.model.PasswordResetToken;
import com.energymonitor.security.infrastructure.JwtKeyedTest;
import jakarta.persistence.EntityManager;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The attempt reservation, against MySQL.
 *
 * <p><strong>Not transactional, deliberately.</strong> A reservation that existed only inside a
 * transaction nobody commits would prove nothing, and a class-level {@code @Transactional} would
 * hold the very row these workers update: each one would wait for the test's own uncommitted insert
 * and fail on a lock timeout instead of on the behaviour under test. That is not hypothetical, it is
 * what happened when these cases first lived in {@code TokenSessionPersistenceTest}, which is
 * {@code @Transactional}: the failure was {@code Lock wait timeout exceeded} on the reservation
 * itself.
 *
 * <p>Running without a rollback means the suite cleans up after itself in
 * {@link #removeEveryRowItCreated()}, scoped to the identifiers used here so a row this suite did
 * not create is never touched.
 *
 * <p>The fixture row is written through the real adapter and hashed by the real hasher, so what is
 * contended is the same row the application writes.
 */
@SpringBootTest
class PasswordResetTokenReservationTest extends JwtKeyedTest {

    private static final String TOKEN_ID = "rst0000001";
    private static final String USER_ID = "use0000001";
    private static final String PERSON_ID = "per0000001";
    private static final String CLEAR_CODE = "795024";
    private static final Instant OPENED_AT = Instant.parse("2026-01-02T03:04:05Z");
    private static final Instant EXPIRES_AT = OPENED_AT.plus(Duration.ofMinutes(15));

    @Autowired
    private PersonPersistenceAdapter persons;
    @Autowired
    private UserPersistenceAdapter users;
    @Autowired
    private PasswordResetTokenPersistenceAdapter passwordResetTokens;
    @Autowired
    private com.energymonitor.security.application.port.out.PasswordResetTokenHasherPort
            resetTokenHasher;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private PlatformTransactionManager transactions;

    /**
     * Widens the connection pool for this class only.
     *
     * <p>Still necessary, and the reason is mechanical rather than convenient: sixty callers
     * arriving together each need a connection to run their single conditional UPDATE. With
     * Hikari's default of ten, the extra fifty queue until the acquire timeout and the probe fails
     * with "Connection is not available" instead of reporting how many attempts were granted. A
     * pool wide enough for the burst is what lets the row itself be the contended resource, which is
     * the thing under test.
     *
     * <p>It is not a statement that production should run a pool this size. A caller that has spent
     * its allowance is refused by the limiter, which keeps its counters in memory and runs before
     * anything opens a connection; {@code ResetAttemptLimiterBeforeDatabaseTest} pins that ordering.
     * What this class demonstrates is the limit that arrives when many callers each still have
     * allowance left, and for that the database does have to serve them all at once.
     */
    @DynamicPropertySource
    static void widenThePool(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> 70);
        registry.add("spring.datasource.hikari.connection-timeout", () -> 60000);
    }

    @AfterEach
    void removeEveryRowItCreated() {
        inCommittedTransaction(() -> {
            entityManager.createNativeQuery(
                    "DELETE FROM password_reset_token WHERE id_reset_token = ?1")
                    .setParameter(1, TOKEN_ID).executeUpdate();
            entityManager.createNativeQuery("DELETE FROM user WHERE id_user = ?1")
                    .setParameter(1, USER_ID).executeUpdate();
            entityManager.createNativeQuery("DELETE FROM person WHERE id_person = ?1")
                    .setParameter(1, PERSON_ID).executeUpdate();
            return null;
        });
    }

    private void seedTokenFor(String idUser, String clearCode) {
        PersistenceFixtures.seedUser(persons, users);
        inCommittedTransaction(() -> {
            passwordResetTokens.save(PasswordResetToken.issue(TOKEN_ID, USER_ID, clearCode,
                    resetTokenHasher.hash(idUser, clearCode), OPENED_AT, EXPIRES_AT));
            return null;
        });
    }

    private int storedAttempts() {
        return inCommittedTransaction(() -> passwordResetTokens.findActive(TOKEN_ID)
                .map(PasswordResetToken::attempts).orElse(-1));
    }

    @Test
    @DisplayName("the reservation is granted up to the budget and refused after it")
    void reservationStopsAtTheBudget() {
        seedTokenFor(USER_ID, CLEAR_CODE);

        for (int attempt = 1; attempt <= 5; attempt++) {
            assertThat(inCommittedTransaction(() -> passwordResetTokens.reserveAttempt(TOKEN_ID)))
                    .as("attempt %d of the budget", attempt)
                    .isTrue();
        }
        assertThat(inCommittedTransaction(() -> passwordResetTokens.reserveAttempt(TOKEN_ID)))
                .as("the attempt after the budget")
                .isFalse();
        assertThat(storedAttempts()).isEqualTo(5);
    }

    @Test
    @DisplayName("a used code is refused while attempts still remain")
    void reservationRefusesAUsedCode() {
        seedTokenFor(USER_ID, CLEAR_CODE);
        assertThat(inCommittedTransaction(() -> passwordResetTokens.markUsedIfPending(TOKEN_ID)))
                .isTrue();

        assertThat(inCommittedTransaction(() -> passwordResetTokens.reserveAttempt(TOKEN_ID)))
                .isFalse();
        assertThat(storedAttempts()).isZero();
    }

    @Test
    @DisplayName("a spent attempt survives the rollback of the request that spent it")
    void reservationSurvivesTheRollbackOfTheRequest() {
        // The reason the reservation opens its own transaction. This rejects its own transaction on
        // purpose and then reads the count back from a different one: written inside the request's
        // transaction, the rollback would carry it away and the fifth attempt would never be counted.
        seedTokenFor(USER_ID, CLEAR_CODE);

        assertThrows(RollbackSentinel.class, () -> inCommittedTransaction(() -> {
            passwordResetTokens.reserveAttempt(TOKEN_ID);
            throw new RollbackSentinel();
        }));

        assertThat(storedAttempts())
                .as("the reservation was rolled back together with the request that spent it")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("a code whose budget is already spent reserves nothing")
    void anExhaustedCodeRefusesEveryReservation() {
        seedTokenFor(USER_ID, CLEAR_CODE);
        runConcurrently(60, () -> inCommittedTransaction(
                () -> passwordResetTokens.reserveAttempt(TOKEN_ID)));

        // A second wave, after the budget was exhausted by the first.
        assertThat(runConcurrently(20, () -> inCommittedTransaction(
                () -> passwordResetTokens.reserveAttempt(TOKEN_ID))))
                .as("an exhausted code must stay exhausted")
                .isZero();
        assertThat(storedAttempts()).isEqualTo(5);
    }

    @Test
    @DisplayName("exactly one of many concurrent redemptions consumes the code")
    void onlyOneConcurrentRedemptionConsumesTheCode() {
        seedTokenFor(USER_ID, CLEAR_CODE);

        int winners = runConcurrently(16,
                () -> inCommittedTransaction(() -> passwordResetTokens.markUsedIfPending(TOKEN_ID)));

        assertThat(winners)
                .as("a code is redeemable once, however many requests arrive together")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("sixty parallel guesses buy exactly five comparisons, not five each")
    void parallelAttemptsAreCappedAtTheBudget() {
        seedTokenFor(USER_ID, CLEAR_CODE);

        int callers = 60;
        int granted = runConcurrently(callers,
                () -> inCommittedTransaction(() -> passwordResetTokens.reserveAttempt(TOKEN_ID)));

        assertThat(granted)
                .as("%d callers were granted %d attempts; the budget is per code, not per caller",
                        callers, granted)
                .isEqualTo(5);
        assertThat(storedAttempts())
                .as("every granted reservation must be visible in the stored count")
                .isEqualTo(5);
    }

    /** Thrown by a test to make its own transaction roll back. */
    private static final class RollbackSentinel extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private <T> T inCommittedTransaction(Callable<T> work) {
        return new TransactionTemplate(transactions).execute(status -> {
            try {
                return work.call();
            } catch (RuntimeException failure) {
                throw failure;
            } catch (Exception checked) {
                throw new IllegalStateException(checked);
            }
        });
    }

    /**
     * Releases every worker on the same signal so they contend for the row instead of taking turns.
     *
     * @param callers how many workers to start
     * @param work    what each of them does
     * @return how many of them answered {@code true}
     */
    private int runConcurrently(int callers, Callable<Boolean> work) {
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        try {
            CountDownLatch startTogether = new CountDownLatch(1);
            List<Future<Boolean>> results = new ArrayList<>();
            for (int worker = 0; worker < callers; worker++) {
                results.add(pool.submit(() -> {
                    startTogether.await();
                    return work.call();
                }));
            }
            startTogether.countDown();
            int granted = 0;
            for (Future<Boolean> result : results) {
                if (Boolean.TRUE.equals(result.get(60, TimeUnit.SECONDS))) {
                    granted++;
                }
            }
            return granted;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("the concurrent probe was interrupted", interrupted);
        } catch (Exception failure) {
            throw new IllegalStateException("the concurrent probe could not complete", failure);
        } finally {
            pool.shutdownNow();
        }
    }
}