package com.energymonitor.security.application.port.out;

import com.energymonitor.security.domain.model.PasswordResetToken;
import java.util.List;
import java.util.Optional;

/**
 * Output port for persisting {@link PasswordResetToken}.
 */
public interface PasswordResetTokenPersistencePort {

    /**
     * Inserts a token.
     *
     * @param token the domain object
     * @return the same domain object
     */
    PasswordResetToken save(PasswordResetToken token);

    /**
     * Updates the state (used flag) of a stored token.
     *
     * @param token the domain object holding the new state
     * @return the same domain object
     */
    PasswordResetToken update(PasswordResetToken token);

    /**
     * Reserves one redemption attempt, atomically, and reports whether it was granted.
     *
     * <p>This is the reservation, not a record of an attempt that already happened. It has to be a
     * single conditional statement because the alternative has a window: if the count were read,
     * then compared against the code, and only then written back, two requests arriving together
     * would both read the same value and both proceed. Here the increment and the check are the
     * same statement, so a code with no attempts left is refused to whoever asks next, no matter
     * how many ask at once.
     *
     * <p>Refused also when the code is already used, so a spent code cannot be probed with
     * attempts.
     *
     * @param idResetToken the code being presented
     * @return {@code true} if an attempt was reserved and the caller may compare the code,
     *         {@code false} if the code is used, exhausted or unknown
     */
    boolean reserveAttempt(String idResetToken);

    /**
     * Consumes a code, but only if it is not already consumed.
     *
     * <p>Conditional for the same reason {@link #reserveAttempt} is: a redemption that two
     * requests both believe they performed must leave exactly one of them the winner, and the
     * loser must not be told by an exception raised after the fact.
     *
     * @param idResetToken the code that was redeemed
     * @return {@code true} if this call is the one that consumed it
     */
    boolean markUsedIfPending(String idResetToken);

    /**
     * Finds the active token by identifier.
     *
     * @param idResetToken the identifier
     * @return the domain object, empty when soft-deleted or missing
     */
    Optional<PasswordResetToken> findActive(String idResetToken);

    /**
     * Finds the active token by the hash of its code.
     *
     * <p>The port takes a hash and not a code: a caller that has a code hashes it first through
     * {@link PasswordResetTokenHasherPort}, so no clear value ever reaches the store.
     *
     * <p><strong>Not the path a redemption takes.</strong> The digest is bound to one account, so
     * a lookup by it can only ever find the token of that account, which is the property the
     * redemption flow relies on; but it also means the row is found by a value derived from a
     * guess. Redemption resolves the account first and its own pending code, then compares.
     *
     * @param resetTokenHash the hash to resolve
     * @return the domain object, empty when soft-deleted or unknown
     */
    Optional<PasswordResetToken> findActiveByHash(String resetTokenHash);

    /**
     * Lists the active tokens of a user, newest first.
     *
     * @param idUser the recipient
     * @return the pending tokens
     */
    List<PasswordResetToken> listActiveByUser(String idUser);

    /**
     * Consumes every token a user currently holds, so that only the newest one can be redeemed.
     *
     * <p>This exists because a recovery code is a small space and guessing is only bounded by how
     * slow the endpoint is. Letting an account hold several live codes at once would let an
     * attacker spend the allowance against all of them, which turns a limit of ten into ten times
     * ten. One live code per account is what makes a per-caller limit mean what it says.
     *
     * <p>Consuming rather than deleting: the rows keep the evidence that codes were issued.
     *
     * @param idUser the account whose codes are being superseded
     * @return how many codes were consumed
     */
    int consumeAllForUser(String idUser);
}
