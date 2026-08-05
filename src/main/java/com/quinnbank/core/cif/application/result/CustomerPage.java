package com.quinnbank.core.cif.application.result;

import java.util.List;

public record CustomerPage(
        List<CustomerSnapshot> customers,
        int page,
        int size,
        long totalElements
) {
}
