package com.quinnbank.core.cif.application.port.in;

import com.quinnbank.core.cif.application.result.CustomerSnapshot;

import java.util.UUID;

public interface GetCustomerUseCase {
    CustomerSnapshot getCustomer(UUID customerId);

    CustomerSnapshot getCustomerByNumber(String customerNumber);
}
