package com.energymonitor.security.adapter.out.backend;

import com.energymonitor.security.api.AccountDeletionBlockedException;
import com.energymonitor.security.application.exception.AccountDeletionCheckUnavailableException;
import com.energymonitor.security.application.port.out.AccountDeletionGuardPort;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Asks energy-monitor-backend {@code GET /internal/accounts/{id}/deletion-check}: 204 lets the
 * deletion go ahead, 409 refuses it with the message to show. Anything else, or no answer within
 * the timeouts, refuses it as unavailable: deleting without the answer could leave a home with
 * members and no owner.
 */
public class HttpAccountDeletionGuard implements AccountDeletionGuardPort {

    static final String DEFAULT_REFUSAL = "Your account cannot be deleted yet.";

    private final RestClient backend;

    /**
     * @param backend client with the backend's base URL, the timeouts and the internal token
     */
    public HttpAccountDeletionGuard(RestClient backend) {
        this.backend = backend;
    }

    @Override
    public void ensureDeletable(String idUser) {
        try {
            backend.get()
                    .uri("/internal/accounts/{idUser}/deletion-check", idUser)
                    .exchange((request, response) -> {
                        if (response.getStatusCode().isSameCodeAs(HttpStatus.NO_CONTENT)) {
                            return null;
                        }
                        if (response.getStatusCode().isSameCodeAs(HttpStatus.CONFLICT)) {
                            throw new AccountDeletionBlockedException(refusal(response.bodyTo(Refusal.class)));
                        }
                        throw new AccountDeletionCheckUnavailableException(
                                "deletion check answered " + response.getStatusCode().value());
                    });
        } catch (RestClientException unreachable) {
            throw new AccountDeletionCheckUnavailableException("deletion check failed", unreachable);
        }
    }

    private static String refusal(Refusal body) {
        return body == null || body.message() == null || body.message().isBlank()
                ? DEFAULT_REFUSAL : body.message();
    }

    /** The body of a 409. */
    record Refusal(String message) {
    }
}
