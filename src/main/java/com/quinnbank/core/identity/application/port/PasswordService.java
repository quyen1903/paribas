package com.quinnbank.core.identity.application.port;

import com.quinnbank.core.identity.domain.EncodedPassword;

public interface PasswordService {
    EncodedPassword encode(String rawPassword);

    boolean matches(String rawPassword, String encodedPassword);

    void performDummyMatch(String rawPassword);
}
