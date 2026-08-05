package com.quinnbank.core.cif.application.port.in;

import com.quinnbank.core.cif.application.query.ListCustomersQuery;
import com.quinnbank.core.cif.application.result.CustomerPage;

public interface ListCustomersUseCase {
    CustomerPage listCustomers(ListCustomersQuery query);
}
