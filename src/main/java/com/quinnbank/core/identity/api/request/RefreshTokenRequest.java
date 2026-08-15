package com.quinnbank.core.identity.api.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshTokenRequest(
    @NotBlank
    @Size(max = 4096)
    String refreshToken
) {
    @Override
    public String toString() {
        return "RefreshTokenRequest[refreshToken=REDACTED]";
    }
}
