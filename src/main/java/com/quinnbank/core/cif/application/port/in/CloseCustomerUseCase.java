package com.quinnbank.core.cif.application.port.in;

import java.util.UUID;

public interface CloseCustomerUseCase {
    void closeCustomer(UUID customerId);
}
