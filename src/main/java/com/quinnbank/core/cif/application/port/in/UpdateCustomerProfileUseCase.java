package com.quinnbank.core.cif.application.port.in;

import com.quinnbank.core.cif.application.command.UpdateCustomerCommand;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;

public interface UpdateCustomerProfileUseCase {
    CustomerSnapshot updateCustomerProfile(UpdateCustomerCommand command);
}
