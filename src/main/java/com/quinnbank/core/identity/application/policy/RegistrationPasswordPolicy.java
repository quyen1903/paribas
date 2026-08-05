package com.quinnbank.core.identity.application.policy;

import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

public final class RegistrationPasswordPolicy {
    private static final int MINIMUM_CHARACTER_COUNT = 12;
    private static final int MAXIMUM_UTF8_BYTE_COUNT = 72;

    public void validate(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword is required.");
        }
        if (rawPassword.codePointCount(0, rawPassword.length()) < MINIMUM_CHARACTER_COUNT) {
            throw new IllegalArgumentException("Password must contain at least 12 characters.");
        }
        if (rawPassword.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Password contains an invalid control character.");
        }
        if (utf8Length(rawPassword) > MAXIMUM_UTF8_BYTE_COUNT) {
            throw new IllegalArgumentException("Password must not exceed 72 UTF-8 bytes.");
        }
    }

    private static int utf8Length(String rawPassword) {
        try {
            return StandardCharsets.UTF_8.newEncoder()
                    .encode(CharBuffer.wrap(rawPassword))
                    .remaining();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("Password contains invalid Unicode data.");
        }
    }
}
