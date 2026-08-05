package com.quinnbank.core.cif.api.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterCustomerRequest(
    @NotBlank
    @Size(max = 100)
    String firstName,

    @NotBlank
    @Size(max = 100)
    String lastName,

    @NotBlank
    @Email
    @Size(max = 254)
    String email,

    @NotBlank
    @Size(max = 50)
    @Pattern(regexp = "^\\+?[0-9 .()\\-]{7,50}$")
    String phone
) {}
