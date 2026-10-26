package com.energymonitor.security.adapter.out.backend;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import com.energymonitor.security.api.AccountDeletionBlockedException;
import com.energymonitor.security.application.exception.AccountDeletionCheckUnavailableException;
import java.io.IOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

@DisplayName("Account deletion guard over HTTP")
class HttpAccountDeletionGuardTest {

    private static final String CHECK = "http://backend/internal/accounts/use0000001/deletion-check";

    private final RestClient.Builder builder = RestClient.builder()
            .baseUrl("http://backend")
            .defaultHeader("X-Internal-Token", "secret");
    private final MockRestServiceServer backend = MockRestServiceServer.bindTo(builder).build();
    private final HttpAccountDeletionGuard guard = new HttpAccountDeletionGuard(builder.build());

    @Test
    @DisplayName("204 lets the deletion go ahead")
    void allowed() {
        backend.expect(requestTo(CHECK)).andExpect(method(HttpMethod.GET))
                .andExpect(header("X-Internal-Token", "secret"))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));

        assertThatCode(() -> guard.ensureDeletable("use0000001")).doesNotThrowAnyException();
        backend.verify();
    }

    @Test
    @DisplayName("409 refuses it with the backend's message")
    void blocked() {
        backend.expect(requestTo(CHECK)).andRespond(withStatus(HttpStatus.CONFLICT)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"message\":\"Transfer the ownership first.\"}"));

        assertThatThrownBy(() -> guard.ensureDeletable("use0000001"))
                .isInstanceOf(AccountDeletionBlockedException.class)
                .hasMessage("Transfer the ownership first.");
    }

    @Test
    @DisplayName("409 without a message still refuses it")
    void blockedWithoutMessage() {
        backend.expect(requestTo(CHECK)).andRespond(withStatus(HttpStatus.CONFLICT)
                .contentType(MediaType.APPLICATION_JSON).body("{}"));

        assertThatThrownBy(() -> guard.ensureDeletable("use0000001"))
                .isInstanceOf(AccountDeletionBlockedException.class)
                .hasMessage(HttpAccountDeletionGuard.DEFAULT_REFUSAL);
    }

    @Test
    @DisplayName("a server error is no answer")
    void serverError() {
        backend.expect(requestTo(CHECK)).andRespond(withServerError());

        assertThatThrownBy(() -> guard.ensureDeletable("use0000001"))
                .isInstanceOf(AccountDeletionCheckUnavailableException.class);
    }

    @Test
    @DisplayName("an unreachable backend is no answer")
    void unreachable() {
        backend.expect(requestTo(CHECK)).andRespond(withException(new IOException("refused")));

        assertThatThrownBy(() -> guard.ensureDeletable("use0000001"))
                .isInstanceOf(AccountDeletionCheckUnavailableException.class);
    }

    @Test
    @DisplayName("a refused token is no answer, not a permission to delete")
    void forbidden() {
        backend.expect(requestTo(CHECK)).andRespond(withStatus(HttpStatus.FORBIDDEN));

        assertThatThrownBy(() -> guard.ensureDeletable("use0000001"))
                .isInstanceOf(AccountDeletionCheckUnavailableException.class);
    }
}
