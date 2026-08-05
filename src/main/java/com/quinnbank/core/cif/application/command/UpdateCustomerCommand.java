package com.quinnbank.core.cif.application.command;

import java.util.UUID;

public record UpdateCustomerCommand(
        UUID customerId,
        String firstName,
        String lastName,
        String email,
        String phone
) {
}
