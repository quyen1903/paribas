package com.quinnbank.core.cif.api;

import com.quinnbank.core.cif.application.result.CustomerSnapshot;
import com.quinnbank.core.cif.application.service.GetCurrentCustomerService;
import com.quinnbank.core.cif.domain.enums.CustomerStatus;
import com.quinnbank.core.web.CorrelationIdContext;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

class CurrentCustomerControllerTest {
    @Test
    void currentCustomerResponseIsNotCachedAndContainsOnlyTheResolvedProfile() throws Exception {
        UUID customerId = UUID.fromString("20000000-0000-0000-0000-000000000002");
        GetCurrentCustomerService service = mock(GetCurrentCustomerService.class);
        when(service.getCurrentCustomer(anyString())).thenReturn(new CustomerSnapshot(
            customerId,
            "CIF20000000000000000000000000000002",
            "Synthetic",
            "Customer",
            "current-customer@example.invalid",
            "+1-555-0100",
            CustomerStatus.ACTIVE,
            LocalDateTime.parse("2026-08-19T08:00:00"),
            LocalDateTime.parse("2026-08-19T08:00:00")
        ));
        MockMvc mockMvc = standaloneSetup(new CurrentCustomerController(service)).build();

        mockMvc.perform(get("/api/v1/customers/me")
                .requestAttr(CorrelationIdContext.REQUEST_ATTRIBUTE, "current-customer-controller-test"))
            .andExpect(status().isOk())
            .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
            .andExpect(jsonPath("$.id").value(customerId.toString()))
            .andExpect(jsonPath("$.customerNumber").value("CIF20000000000000000000000000000002"));
    }
}
