package com.energymonitor.security.application.exception;

/**
 * The account, or the one about to be created, has not accepted the terms and conditions. The
 * client shows them and repeats the request with {@code acceptTerms: true}.
 */
public class TermsNotAcceptedException extends SecurityApplicationException {

    public TermsNotAcceptedException(String message) {
        super(message);
    }
}
