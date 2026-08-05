package com.quinnbank.core.cif.api.response;

import java.util.List;

public record CustomerPageResponse(
        List<CustomerResponse> customers,
        int page,
        int size,
        long totalElements
) {
}
