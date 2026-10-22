package com.energymonitor.security.adapter.out.persistence.repository;

import com.energymonitor.security.adapter.out.persistence.entity.PasswordResetTokenEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository over {@code password_reset_token}.
 *
 * <p>No finder takes a raw code, so there is no path that could query the table with a usable
 * credential. The two mutating statements are hand-written because their correctness depends on
 * being a single statement each, which a derived query method cannot express.
 */
@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetTokenEntity, String> {

    /**
     * Finds the active token whose stored hash matches.
     *
     * @param resetTokenHash the hash of the secret to resolve
     * @return the row, empty when soft-deleted or unknown
     */
    Optional<PasswordResetTokenEntity> findByResetTokenHashAndDeletedAtIsNull(String resetTokenHash);

    /**
     * Lists the active tokens issued to a user, newest first.
     *
     * <p>A user may hold several pending tokens; picking the right one to consume is the
     * caller's decision, but a deterministic order keeps it stable.
     *
     * @param userId the recipient
     * @return the pending tokens, newest first
     */
    List<PasswordResetTokenEntity> findByUserIdAndDeletedAtIsNullOrderByCreatedAtDesc(String userId);

    /**
     * The pending tokens of a user, for the purpose of consuming them in one statement.
     *
     * <p>Mutating in bulk rather than entity by entity, because the whole point is that this runs
     * immediately before issuing a new code and there is no reason to hold the rows in memory or
     * to issue one statement per token.
     *
     * @param userId the recipient
     * @return the tokens to consume, newest first
     */
    List<PasswordResetTokenEntity> findByUserIdAndUsedFalseAndDeletedAtIsNullOrderByCreatedAtDesc(
            String userId);

    /**
     * Reserves one attempt on a code that is still usable, and only that.
     *
     * <p>The reservation is one statement on purpose. A derived method would need the count read
     * first and written afterwards, and that gap is exactly what lets concurrent requests share an
     * allowance each was supposed to have to itself.
     *
     * <p>The {@code attempts < 5} predicate is the comparison budget written as SQL, so it is
     * evaluated by the same statement that spends it. Keeping the number here rather than in the
     * domain is a deliberate duplication: the column is the authority under concurrency, and a
     * value held in Java could not be the one that decides.
     *
     * <p>No lock clause, and deliberately so. This statement only writes, so concurrent attempts
     * contend for the row lock and InnoDB makes the second wait for the first to commit, which is
     * what keeps the count exact. A pessimistic read would be worse, not safer: it would hold that
     * row for the length of the code comparison, so every other attempt behind it waited on the
     * slowest comparison rather than on a single statement. The wait here is bounded by one
     * statement, and nothing in the flow holds a row open across the comparison.
     *
     * @param idResetToken the code being presented
     * @return 1 when the attempt was reserved and the caller may compare, 0 otherwise
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update PasswordResetTokenEntity t set t.attempts = t.attempts + 1"
            + " where t.idResetToken = :idResetToken"
            + " and t.used = false"
            + " and t.attempts < 5"
            + " and t.deletedAt is null")
    int reserveAttempt(@Param("idResetToken") String idResetToken);

    /**
     * Consumes a code only while it is unconsumed, so exactly one of several concurrent
     * redemptions of the same code can report success.
     *
     * <p>Conditional for the same reason {@link #reserveAttempt} is: a redemption that two requests
     * both believe they performed has to leave one winner, and the other must not learn it lost by
     * an exception raised after the fact.
     *
     * @param idResetToken the code that was redeemed
     * @return 1 for the redemption that consumed it, 0 for the others
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update PasswordResetTokenEntity t set t.used = true"
            + " where t.idResetToken = :idResetToken"
            + " and t.used = false"
            + " and t.deletedAt is null")
    int markUsedIfPending(@Param("idResetToken") String idResetToken);
}
