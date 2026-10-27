package com.energymonitor.security.application.port.in;

import com.energymonitor.security.application.result.AuthenticatedUser;
import com.energymonitor.security.application.result.GoogleIdentity;
import java.util.Optional;

/**
 * Use case: sign in, or create the account on the first time, with a verified Google identity.
 */
public interface SignInWithGoogle {

    /**
     * @return the signed-in account; empty when Google did not verify the address
     * @throws com.energymonitor.security.application.exception.EmailAlreadyRegisteredException
     *         when the address belongs to an account registered with a password
     * @param acceptTerms whether the person accepts the terms and conditions with this sign-in;
     *                    required to create the account, and for an account that never did
     * @throws com.energymonitor.security.application.exception.AccountNotActiveException
     *         when the account is blocked or inactive
     * @throws com.energymonitor.security.application.exception.TermsNotAcceptedException
     *         when the account would be created, or never accepted the terms, and
     *         {@code acceptTerms} is false
     */
    Optional<AuthenticatedUser> signIn(GoogleIdentity identity, String ipAddress, boolean acceptTerms);
}
