package com.quinnbank.core.cif.application.command;

public record RegisterCustomerCommand(
    String firstName,
    String lastName,
    String email,
    String phone
) {}
