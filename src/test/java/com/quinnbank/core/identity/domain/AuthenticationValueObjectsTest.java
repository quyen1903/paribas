package com.quinnbank.core.identity.domain;

import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticationValueObjectsTest {

    @Test
    void encodedPasswordAcceptsEncoderShapeButRejectsRawOrMalformedValues() {
        String encodedValue = "$2b$12$" + "C".repeat(53);

        EncodedPassword encodedPassword = EncodedPassword.fromPasswordEncoder(encodedValue);

        assertEquals(encodedValue, encodedPassword.value());
        assertThrows(
                IllegalArgumentException.class,
                () -> EncodedPassword.fromPasswordEncoder("synthetic-raw-password")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> EncodedPassword.fromPasswordEncoder("$2b$12$too-short")
        );
    }

    @Test
    void authenticationValueObjectsRedactSecretsAndActorIdentifiers() {
        String encodedValue = "$2b$12$" + "D".repeat(53);
        EncodedPassword encodedPassword = EncodedPassword.fromPasswordEncoder(encodedValue);
        AuthenticationActor actor = AuthenticationActor.of(
                IdentityActorType.BACK_OFFICE_OPERATOR,
                "synthetic-operator-secret-id"
        );

        assertFalse(encodedPassword.toString().contains(encodedValue));
        assertEquals("EncodedPassword[redacted]", encodedPassword.toString());
        assertFalse(actor.toString().contains(actor.id()));
        assertEquals(
                "AuthenticationActor[type=BACK_OFFICE_OPERATOR, id=redacted]",
                actor.toString()
        );
    }
}
