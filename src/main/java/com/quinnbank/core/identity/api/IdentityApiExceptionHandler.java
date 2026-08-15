package com.quinnbank.core.identity.api;

import com.quinnbank.core.identity.api.response.IdentityApiErrorResponse;
import com.quinnbank.core.identity.application.exception.AuthenticationRateLimitExceededException;
import com.quinnbank.core.identity.application.exception.ConcurrentIdentityRegistrationException;
import com.quinnbank.core.identity.application.exception.IdentityAlreadyExistsException;
import com.quinnbank.core.identity.application.exception.InvalidCredentialsException;
import com.quinnbank.core.identity.application.exception.InvalidIdentityRegistrationException;
import com.quinnbank.core.identity.application.exception.InvalidRefreshTokenException;
import com.quinnbank.core.identity.application.exception.SigningKeyUnavailableException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = IdentityAuthenticationController.class)
public class IdentityApiExceptionHandler {
    @ExceptionHandler(IdentityAlreadyExistsException.class)
    public ResponseEntity<IdentityApiErrorResponse> identityAlreadyExists(HttpServletRequest request) {
        return error(
            HttpStatus.CONFLICT,
            "REGISTRATION_CONFLICT",
            "Identity registration could not be completed.",
            request
        );
    }

    @ExceptionHandler(ConcurrentIdentityRegistrationException.class)
    public ResponseEntity<IdentityApiErrorResponse> concurrentRegistrationConflict(HttpServletRequest request) {
        return error(
            HttpStatus.CONFLICT,
            "REGISTRATION_CONFLICT",
            "Identity registration could not be completed.",
            request
        );
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<IdentityApiErrorResponse> invalidCredentials(HttpServletRequest request) {
        return error(
            HttpStatus.UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "The login identifier or password is invalid.",
            request
        );
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<IdentityApiErrorResponse> invalidRefreshToken(HttpServletRequest request) {
        return error(
            HttpStatus.UNAUTHORIZED,
            "INVALID_REFRESH_TOKEN",
            "The refresh token is invalid or expired.",
            request
        );
    }

    @ExceptionHandler(AuthenticationRateLimitExceededException.class)
    public ResponseEntity<IdentityApiErrorResponse> rateLimitExceeded(HttpServletRequest request) {
        return error(
            HttpStatus.TOO_MANY_REQUESTS,
            "AUTHENTICATION_RATE_LIMIT_EXCEEDED",
            "Too many authentication attempts. Try again later.",
            request
        );
    }

    @ExceptionHandler(SigningKeyUnavailableException.class)
    public ResponseEntity<IdentityApiErrorResponse> signingKeyUnavailable(HttpServletRequest request) {
        return error(
            HttpStatus.SERVICE_UNAVAILABLE,
            "SIGNING_KEY_UNAVAILABLE",
            "Authentication is temporarily unavailable.",
            request
        );
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<IdentityApiErrorResponse> validation(
            MethodArgumentNotValidException exception,
            HttpServletRequest request
    ) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError fieldError : exception.getBindingResult().getFieldErrors()) {
            fieldErrors.putIfAbsent(fieldError.getField(), "Invalid value.");
        }

        return ResponseEntity
            .badRequest()
            .cacheControl(CacheControl.noStore())
            .body(IdentityApiErrorResponse.validation(correlationId(request), fieldErrors));
    }

    @ExceptionHandler(InvalidIdentityRegistrationException.class)
    public ResponseEntity<IdentityApiErrorResponse> invalidRegistration(HttpServletRequest request) {
        return error(
            HttpStatus.BAD_REQUEST,
            "INVALID_REGISTRATION_REQUEST",
            "The identity registration request is invalid.",
            request
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<IdentityApiErrorResponse> unreadableRequest(HttpServletRequest request) {
        return error(
            HttpStatus.BAD_REQUEST,
            "MALFORMED_REQUEST",
            "The request body is invalid.",
            request
        );
    }

    private static ResponseEntity<IdentityApiErrorResponse> error(
        HttpStatus status,
        String code,
        String message,
        HttpServletRequest request
    ) {
        return ResponseEntity
            .status(status)
            .cacheControl(CacheControl.noStore())
            .body(IdentityApiErrorResponse.of(code, message, correlationId(request)));
    }

    private static String correlationId(HttpServletRequest request) {
        Object value = request.getAttribute(CorrelationIdFilter.REQUEST_ATTRIBUTE);
        return value instanceof String correlationId ? correlationId : "unavailable";
    }
}
