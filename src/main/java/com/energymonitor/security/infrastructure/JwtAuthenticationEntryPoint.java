package com.energymonitor.security.infrastructure;

import com.energymonitor.security.adapter.in.web.dto.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Answers a rejected request with the same {@link ApiError} body the controllers use.
 *
 * <p>Without this, Spring Security's default entry point replies with an empty body or an
 * HTML page, which would give clients two different error shapes to parse and risks leaking
 * framework detail such as the authentication failure reason.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final Clock clock;

    public JwtAuthenticationEntryPoint(ObjectMapper objectMapper, Clock clock) {
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException exception) throws IOException {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(),
                ApiError.of(Instant.now(clock), status.value(), status.getReasonPhrase(),
                        "A valid access token is required.", request.getRequestURI()));
    }
}
