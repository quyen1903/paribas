package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.IdentityActorType;

public final class AuthenticationActor {
    private static final int MAX_ACTOR_ID_LENGTH = 100;

    private final IdentityActorType type;
    private final String id;

    private AuthenticationActor(IdentityActorType type, String id) {
        if (type == null) {
            throw new IllegalArgumentException("type is required.");
        }

        this.type = type;
        this.id = requireText(id, "id", MAX_ACTOR_ID_LENGTH);
    }

    public static AuthenticationActor of(IdentityActorType type, String id) {
        return new AuthenticationActor(type, id);
    }

    public IdentityActorType type() {
        return type;
    }

    public String id() {
        return id;
    }

    @Override
    public String toString() {
        return "AuthenticationActor[type=" + type + ", id=redacted]";
    }

    private static String requireText(String value, String fieldName, int maxLength) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(fieldName + " is required.");
        }

        String trimmed = value.trim();
        if (trimmed.length() > maxLength) {
            throw new IllegalArgumentException(fieldName + " is too long.");
        }
        if (trimmed.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(fieldName + " contains invalid characters.");
        }
        return trimmed;
    }
}
