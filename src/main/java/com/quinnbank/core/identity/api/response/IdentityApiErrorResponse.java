package com.quinnbank.core.identity.api.response;

import java.util.Map;

public record IdentityApiErrorResponse(
    String code,
    String message,
    String correlationId,
    Map<String, String> fieldErrors
) {
    public IdentityApiErrorResponse {
        fieldErrors = Map.copyOf(fieldErrors);
    }

    public static IdentityApiErrorResponse of(String code, String message, String correlationId) {
        return new IdentityApiErrorResponse(code, message, correlationId, Map.of());
    }

    public static IdentityApiErrorResponse validation(String correlationId, Map<String, String> fieldErrors) {
        return new IdentityApiErrorResponse(
            "VALIDATION_FAILED",
            "The request contains invalid fields.",
            correlationId,
            fieldErrors
        );
    }
}
