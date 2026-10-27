package com.energymonitor.security.adapter.in.web;

import com.energymonitor.security.adapter.in.web.dto.ApiError;
import com.energymonitor.security.api.AccountDeletionBlockedException;
import com.energymonitor.security.application.exception.AccountDeletionCheckUnavailableException;
import com.energymonitor.security.application.exception.AccountNotActiveException;
import com.energymonitor.security.application.exception.GoogleSignInUnavailableException;
import com.energymonitor.security.application.exception.CurrentPasswordMismatchException;
import com.energymonitor.security.application.exception.EmailAlreadyRegisteredException;
import com.energymonitor.security.application.exception.EmailNotVerifiedException;
import com.energymonitor.security.application.exception.InvalidResetTokenException;
import com.energymonitor.security.application.exception.InvalidVerificationCodeException;
import com.energymonitor.security.application.exception.PasswordPolicyViolationException;
import com.energymonitor.security.application.exception.RoleNotFoundException;
import com.energymonitor.security.application.exception.SecurityApplicationException;
import com.energymonitor.security.application.exception.SelfAdministrationException;
import com.energymonitor.security.application.exception.TermsNotAcceptedException;
import com.energymonitor.security.application.exception.TooManyResetAttemptsException;
import com.energymonitor.security.application.exception.UndeliverableEmailException;
import com.energymonitor.security.application.exception.SessionNotFoundException;
import com.energymonitor.security.application.exception.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns application and framework failures into the single {@link ApiError} shape.
 *
 * <p>This class is the boundary where an exception stops being an internal detail. Only the
 * status, a message written for the caller and the request path cross it: no exception class,
 * no stack trace, no cause and no SQL reaches a client. The full exception is logged instead,
 * so operators keep the detail that callers must not have.
 *
 * <p>The status codes follow what the failure means to the caller:
 *
 * <ul>
 *   <li>404 - the account, role or session the request named does not exist.</li>
 *   <li>409 - the email is already taken, or an administrator targeted their own account.</li>
 *   <li>400 - the request was malformed or a token in it was not usable.</li>
 *   <li>401 - the presented password did not match.</li>
 *   <li>403 - the account is blocked or inactive.</li>
 *   <li>422 - the password was well-formed but breaks the configured policy.</li>
 *   <li>405 - the route exists, but not for the verb the request used.</li>
 *   <li>429 - the caller is sending password-recovery attempts too fast.</li>
 *   <li>500 - anything unexpected, reported without detail.</li>
 * </ul>
 */
@RestControllerAdvice
public class SecurityExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityExceptionHandler.class);

    private final Clock clock;

    public SecurityExceptionHandler(Clock clock) {
        this.clock = clock;
    }

    /**
     * Bean validation rejected the request body.
     *
     * @param exception the framework failure carrying the per-field errors
     * @param request   the failed request
     * @return 400 with one message per offending field
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException exception,
                                                     HttpServletRequest request) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        exception.getBindingResult().getFieldErrors()
                .forEach(error -> fieldErrors.putIfAbsent(error.getField(),
                        error.getDefaultMessage() == null ? "is invalid"
                                : error.getDefaultMessage()));
        ApiError body = new ApiError(Instant.now(clock), HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(), "Request validation failed.",
                request.getRequestURI(), fieldErrors);
        return ResponseEntity.badRequest().body(body);
    }

    /**
     * The body was absent or not readable as JSON.
     *
     * @param exception the framework failure
     * @param request   the failed request
     * @return 400
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadableBody(HttpMessageNotReadableException exception,
                                                        HttpServletRequest request) {
        LOG.debug("Unreadable request body on {}", request.getRequestURI(), exception);
        return respond(HttpStatus.BAD_REQUEST, "Malformed request body.", request);
    }

    /**
     * A named account, role or session does not exist.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 404
     */
    @ExceptionHandler({UserNotFoundException.class, RoleNotFoundException.class,
            SessionNotFoundException.class})
    public ResponseEntity<ApiError> handleNotFound(SecurityApplicationException exception,
                                                   HttpServletRequest request) {
        LOG.debug("{} on {}", exception.getClass().getSimpleName(), request.getRequestURI());
        return respond(HttpStatus.NOT_FOUND, exception.getMessage(), request);
    }

    /**
     * The email is already registered.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 409
     */
    @ExceptionHandler(EmailAlreadyRegisteredException.class)
    public ResponseEntity<ApiError> handleEmailTaken(EmailAlreadyRegisteredException exception,
                                                     HttpServletRequest request) {
        return respond(HttpStatus.CONFLICT, exception.getMessage(), request);
    }

    /**
     * The caller is going too fast at password recovery.
     *
     * <p>The only refusal here that is not {@code 400}, and deliberately so: {@code 429} with a
     * {@code Retry-After} tells a well-behaved client to come back later, which {@code 400} would
     * not. The message is fixed, so it reports nothing about how many attempts remain or how close
     * a guess had come.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 429
     */
    @ExceptionHandler(TooManyResetAttemptsException.class)
    public ResponseEntity<ApiError> handleTooManyAttempts(TooManyResetAttemptsException exception,
                                                          HttpServletRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, "900");
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).headers(headers)
                .body(ApiError.of(Instant.now(clock),
                        HttpStatus.TOO_MANY_REQUESTS.value(),
                        HttpStatus.TOO_MANY_REQUESTS.getReasonPhrase(),
                        exception.getMessage(), request.getRequestURI()));
    }

    /**
     * A reset code was unknown, already used or expired.
     *
     * @param exception the application failure
     * @return 400
     */
    @ExceptionHandler(InvalidResetTokenException.class)
    public ResponseEntity<ApiError> handleInvalidToken(InvalidResetTokenException exception,
                                                       HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    /**
     * The presented current password did not match.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 401
     */
    @ExceptionHandler(InvalidVerificationCodeException.class)
    public ResponseEntity<ApiError> handleInvalidVerificationCode(
            InvalidVerificationCodeException exception, HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    /**
     * An administrator tried to change their own status or roles.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 409
     */
    @ExceptionHandler(SelfAdministrationException.class)
    public ResponseEntity<ApiError> handleSelfAdministration(SelfAdministrationException exception,
                                                             HttpServletRequest request) {
        return respond(HttpStatus.CONFLICT, exception.getMessage(), request);
    }

    @ExceptionHandler(AccountDeletionBlockedException.class)
    public ResponseEntity<ApiError> handleAccountDeletionBlocked(
            AccountDeletionBlockedException exception, HttpServletRequest request) {
        return respond(HttpStatus.CONFLICT, exception.getMessage(), request);
    }

    /**
     * energy-monitor-backend could not say whether the account may be deleted, so it was not.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 503
     */
    @ExceptionHandler(AccountDeletionCheckUnavailableException.class)
    public ResponseEntity<ApiError> handleDeletionCheckUnavailable(
            AccountDeletionCheckUnavailableException exception, HttpServletRequest request) {
        LOG.warn("Account deletion refused: {}", exception.getMessage());
        return respond(HttpStatus.SERVICE_UNAVAILABLE,
                "Your account cannot be deleted right now. Try again in a few minutes.", request);
    }

    @ExceptionHandler(CurrentPasswordMismatchException.class)
    public ResponseEntity<ApiError> handleWrongCurrentPassword(
            CurrentPasswordMismatchException exception, HttpServletRequest request) {
        return respond(HttpStatus.UNAUTHORIZED, "The current password is not correct.", request);
    }

    /**
     * A login attempt was refused. The reason is deliberately not part of the response.
     *
     * @param exception the delivery-layer signal carrying the generic message
     * @param request   the failed request
     * @return 401
     */
    @ExceptionHandler(AuthenticationRejectedException.class)
    public ResponseEntity<ApiError> handleRejectedAuthentication(
            AuthenticationRejectedException exception, HttpServletRequest request) {
        LOG.debug("Rejected login attempt on {}", request.getRequestURI());
        return respond(HttpStatus.UNAUTHORIZED, exception.getMessage(), request);
    }

    /**
     * No Google client is configured on this server.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 503
     */
    @ExceptionHandler(GoogleSignInUnavailableException.class)
    public ResponseEntity<ApiError> handleGoogleUnavailable(GoogleSignInUnavailableException exception,
                                                            HttpServletRequest request) {
        return respond(HttpStatus.SERVICE_UNAVAILABLE, exception.getMessage(), request);
    }

    /**
     * The account is blocked or inactive.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 403
     */
    @ExceptionHandler(AccountNotActiveException.class)
    public ResponseEntity<ApiError> handleInactiveAccount(AccountNotActiveException exception,
                                                          HttpServletRequest request) {
        return respond(HttpStatus.FORBIDDEN, exception.getMessage(), request);
    }

    /**
     * The password was right but the account has not confirmed its address. Only someone who knows
     * the password gets here, so saying why is safe, and it is what lets the client ask for the
     * verification code instead of showing a generic refusal.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 403
     */
    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<ApiError> handleEmailNotVerified(EmailNotVerifiedException exception,
                                                           HttpServletRequest request) {
        LOG.debug("Sign-in refused until the address is verified on {}", request.getRequestURI());
        return respond(HttpStatus.FORBIDDEN, "Verify your email address to sign in.", request);
    }

    /**
     * The password is well-formed but breaks the configured policy.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 422
     */
    @ExceptionHandler(PasswordPolicyViolationException.class)
    public ResponseEntity<ApiError> handlePolicyViolation(PasswordPolicyViolationException exception,
                                                           HttpServletRequest request) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, exception.getMessage(), request);
    }

    /**
     * The address is well-formed but its domain does not exist or cannot receive mail: a bad
     * address, answered like any other invalid one (422 stays the password policy's).
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 400
     */
    /**
     * The terms and conditions were not accepted: the client shows them and repeats the request
     * with {@code acceptTerms: true}.
     *
     * @return 428
     */
    @ExceptionHandler(TermsNotAcceptedException.class)
    public ResponseEntity<ApiError> handleTermsNotAccepted(TermsNotAcceptedException exception,
                                                           HttpServletRequest request) {
        return respond(HttpStatus.PRECONDITION_REQUIRED, exception.getMessage(), request);
    }

    @ExceptionHandler(UndeliverableEmailException.class)
    public ResponseEntity<ApiError> handleUndeliverableEmail(UndeliverableEmailException exception,
                                                             HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    /**
     * Any other application failure, including ones added later without a handler.
     *
     * @param exception the application failure
     * @param request   the failed request
     * @return 400
     */
    @ExceptionHandler(SecurityApplicationException.class)
    public ResponseEntity<ApiError> handleApplication(SecurityApplicationException exception,
                                                      HttpServletRequest request) {
        LOG.warn("Unhandled application failure on {}", request.getRequestURI(), exception);
        return respond(HttpStatus.BAD_REQUEST, "The request could not be processed.", request);
    }

/**
     * A domain guard rejected the input, for example a malformed address or a blank field.
     *
     * @param exception the domain failure
     * @param request   the failed request
     * @return 400
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgument(IllegalArgumentException exception,
                                                          HttpServletRequest request) {
        LOG.debug("Rejected input on {}", request.getRequestURI(), exception);
        return respond(HttpStatus.BAD_REQUEST, exception.getMessage(), request);
    }

    /**
     * The route exists but not for the verb that was used.
     *
     * <p>Handled explicitly because the fallback below would otherwise answer 500: a client that
     * posts to a route that only accepts PUT has made a request the server understood perfectly
     * well, and reporting it as a server failure hides the one fact that fixes it. The allowed
     * methods are published in the {@code Allow} header, which is the machine-readable half of
     * the same answer.
     *
     * @param exception the framework failure carrying the supported methods
     * @param request   the failed request
     * @return 405
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiError> handleMethodNotAllowed(
            HttpRequestMethodNotSupportedException exception, HttpServletRequest request) {
        LOG.debug("Rejected {} on {}", request.getMethod(), request.getRequestURI());
        String allowed = exception.getSupportedHttpMethods() == null ? ""
                : String.join(", ", exception.getSupportedHttpMethods().stream()
                        .map(method -> method.name()).toList());
        HttpHeaders headers = new HttpHeaders();
        if (!allowed.isEmpty()) {
            headers.set(HttpHeaders.ALLOW, allowed);
        }
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).headers(headers)
                .body(ApiError.of(Instant.now(clock), HttpStatus.METHOD_NOT_ALLOWED.value(),
                        HttpStatus.METHOD_NOT_ALLOWED.getReasonPhrase(),
                        "Method " + request.getMethod() + " is not supported for this resource.",
                        request.getRequestURI()));
    }

    /**
     * A query parameter or path variable could not be converted to its declared type.
     *
     * @param exception the framework failure
     * @param request   the failed request
     * @return 400
     */
    @ExceptionHandler(TypeMismatchException.class)
    public ResponseEntity<ApiError> handleTypeMismatch(TypeMismatchException exception,
                                                       HttpServletRequest request) {
        LOG.debug("Type mismatch on {}", request.getRequestURI(), exception);
        return respond(HttpStatus.BAD_REQUEST, "Malformed request parameter.", request);
    }

    /**
     * Anything unanticipated. The message is generic on purpose and the detail goes to the
     * log only.
     *
     * <p>Failures Spring MVC already classifies ({@link ErrorResponse}: a missing required
     * parameter, an unknown route, an unsupported media type...) keep the framework's status, so
     * a client mistake is not reported as a server failure.
     *
     * @param exception the failure
     * @param request   the failed request
     * @return the framework's status for an {@link ErrorResponse}, otherwise 500 without internals
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception exception,
                                                     HttpServletRequest request) {
        if (exception instanceof ErrorResponse errorResponse) {
            HttpStatus status = HttpStatus.resolve(errorResponse.getStatusCode().value());
            if (status != null && status.is4xxClientError()) {
                LOG.debug("{} on {}", exception.getClass().getSimpleName(), request.getRequestURI());
                return respond(status, null, request);
            }
        }
        LOG.error("Unhandled failure on {}", request.getRequestURI(), exception);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred.", request);
    }

    private ResponseEntity<ApiError> respond(HttpStatus status, String message,
                                            HttpServletRequest request) {
        return ResponseEntity.status(status)
                .body(ApiError.of(Instant.now(clock), status.value(), status.getReasonPhrase(),
                        message == null ? status.getReasonPhrase() : message,
                        request.getRequestURI()));
    }
}
