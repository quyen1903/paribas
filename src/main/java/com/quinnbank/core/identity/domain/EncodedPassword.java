package com.quinnbank.core.identity.domain;

import java.util.regex.Pattern;

/**
 * Opaque password-encoder output. The application layer must create this value
 * only after hashing a raw password with the configured Spring Security
 * {@code PasswordEncoder}.
 */
public final class EncodedPassword {
    private static final Pattern BCRYPT_FORMAT = Pattern.compile(
            "\\$2[aby]\\$\\d{2}\\$[./A-Za-z0-9]{53}"
    );

    private final String value;

    private EncodedPassword(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("encoded password is required.");
        }
        if (!BCRYPT_FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("encoded password format is invalid.");
        }
        this.value = value;
    }

    public static EncodedPassword fromPasswordEncoder(String value) {
        return new EncodedPassword(value);
    }

    String value() {
        return value;
    }

    @Override
    public String toString() {
        return "EncodedPassword[redacted]";
    }
}
