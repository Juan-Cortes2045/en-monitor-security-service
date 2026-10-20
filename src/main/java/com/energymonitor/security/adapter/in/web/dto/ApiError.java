package com.energymonitor.security.adapter.in.web.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.Map;

/**
 * The single error shape every failing Security endpoint returns.
 *
 * <p>One shape for every failure is what lets a client handle errors generically. It carries
 * no stack trace, no exception class name, no cause and no SQL: only the status, a message
 * written for the caller, and the request path. Anything the server knows beyond that stays
 * in the server log.
 *
 * @param timestamp    when the failure was produced
 * @param status       the HTTP status code, repeated in the body for convenience
 * @param error        the reason phrase matching the status
 * @param message      a caller-safe description
 * @param path         the request path that failed
 * @param fieldErrors  per-field validation messages, empty when the failure was not a
 *                     bean-validation failure
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        Map<String, String> fieldErrors) {

    /**
     * @param timestamp when the failure was produced
     * @param status    the HTTP status code
     * @param error     the reason phrase matching the status
     * @param message   a caller-safe description
     * @param path      the request path that failed
     * @return the error body
     */
    public static ApiError of(Instant timestamp, int status, String error, String message, String path) {
        return new ApiError(timestamp, status, error, message, path, Map.of());
    }
}
