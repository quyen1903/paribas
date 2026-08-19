package com.quinnbank.core.cif.api;

import com.quinnbank.core.cif.api.response.CustomerResponse;
import com.quinnbank.core.cif.application.service.GetCurrentCustomerService;
import com.quinnbank.core.web.CorrelationIdContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/customers")
public class CurrentCustomerController {
    private final GetCurrentCustomerService getCurrentCustomer;

    public CurrentCustomerController(GetCurrentCustomerService getCurrentCustomer) {
        this.getCurrentCustomer = getCurrentCustomer;
    }

    @GetMapping("/me")
    @PreAuthorize("hasAuthority('actor:retail_customer')")
    public ResponseEntity<CustomerResponse> getCurrent(HttpServletRequest request) {
        return ResponseEntity
            .ok()
            .cacheControl(CacheControl.noStore())
            .body(CustomerResponse.from(getCurrentCustomer.getCurrentCustomer(
                CorrelationIdContext.get(request)
            )));
    }
}
