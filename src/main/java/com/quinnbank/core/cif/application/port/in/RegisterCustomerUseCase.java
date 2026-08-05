package com.quinnbank.core.cif.application.port.in;

import com.quinnbank.core.cif.application.command.RegisterCustomerCommand;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;

public interface RegisterCustomerUseCase {
    CustomerSnapshot registerCustomer(RegisterCustomerCommand command);
}
