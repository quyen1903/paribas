package com.quinnbank.core.identity.api.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterIdentityRequest(
    @NotBlank
    @Size(max = 254)
    String loginIdentifier,

    @NotBlank
    @Size(max = 128)
    String password
) {
    @Override
    public String toString() {
        return "RegisterIdentityRequest[REDACTED]";
    }
}
