package com.energymonitor.security.application.exception;

/**
 * Base for the application-layer exceptions. Nothing technology-specific lives here.
 */
public class SecurityApplicationException extends RuntimeException {

    public SecurityApplicationException(String message) {
        super(message);
    }

    public SecurityApplicationException(String message, Throwable cause) {
        super(message, cause);
    }
}