package com.example.notes;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestClientException;

/**
 * Turns controller exceptions into the contract's error body.
 *
 * <p>There is deliberately no catch-all handler: an AccessDeniedException thrown by
 * {@code @PreAuthorize} must travel on to Spring Security, which answers 403 through the
 * AccessDeniedHandler in {@link SecurityConfig}.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    ResponseEntity<ApiError> api(ApiException e) {
        return ResponseEntity.status(e.status()).body(ApiError.of(e.code(), e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> unreadableBody() {
        return ResponseEntity.badRequest().body(ApiError.of("invalid_json", "request body must be JSON"));
    }

    /** Keyora is down, timed out, or answered with something that is not its envelope. */
    @ExceptionHandler({RestClientException.class, KeyoraClient.UnexpectedResponseException.class})
    ResponseEntity<ApiError> keyoraUnavailable(Exception e) {
        log.warn("call to Keyora failed: {}", e.toString());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(ApiError.of("identity_unavailable", "the identity service is unavailable"));
    }
}
