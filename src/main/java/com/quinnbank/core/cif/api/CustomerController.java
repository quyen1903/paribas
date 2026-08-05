package com.quinnbank.core.cif.api;

import com.quinnbank.core.cif.api.request.RegisterCustomerRequest;
import com.quinnbank.core.cif.api.request.UpdateCustomerRequest;
import com.quinnbank.core.cif.api.response.CustomerResponse;
import com.quinnbank.core.cif.application.command.RegisterCustomerCommand;
import com.quinnbank.core.cif.application.command.UpdateCustomerCommand;
import com.quinnbank.core.cif.application.port.in.CloseCustomerUseCase;
import com.quinnbank.core.cif.application.port.in.RegisterCustomerUseCase;
import com.quinnbank.core.cif.application.port.in.UpdateCustomerProfileUseCase;
import com.quinnbank.core.cif.application.result.CustomerSnapshot;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/customers")
public class CustomerController {
    private final RegisterCustomerUseCase registerCustomerUseCase;
    private final UpdateCustomerProfileUseCase updateCustomerProfile;
    private final CloseCustomerUseCase closeCustomer;

    public CustomerController(
        RegisterCustomerUseCase registerCustomerUseCase,
        UpdateCustomerProfileUseCase updateCustomerProfile,
        CloseCustomerUseCase closeCustomer
    ) {
        this.registerCustomerUseCase = registerCustomerUseCase;
        this.updateCustomerProfile = updateCustomerProfile;
        this.closeCustomer = closeCustomer;
    }

    @DeleteMapping("/{customerId}")
    @PreAuthorize("hasAuthority('cif:write')")
    public ResponseEntity<Void> close(@PathVariable UUID customerId) {
        closeCustomer.closeCustomer(customerId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/register")
    @PreAuthorize("hasAuthority('cif:write')")
    public ResponseEntity<CustomerResponse> register(
        @Valid
        @RequestBody
        RegisterCustomerRequest request
    ){
        RegisterCustomerCommand command = new RegisterCustomerCommand(
            request.firstName(),
            request.lastName(),
            request.email(),
            request.phone()
        );

        CustomerSnapshot customer = registerCustomerUseCase.registerCustomer(command);
        return ResponseEntity.status(HttpStatus.CREATED).body(CustomerResponse.from(customer));
    }

    @PatchMapping("update")
    @PreAuthorize("hasAuthority('cif:write')")
    public ResponseEntity<CustomerResponse> update(
        @Valid
        @RequestBody
        UpdateCustomerRequest request
    ){
        UpdateCustomerCommand command = new UpdateCustomerCommand(
            request.id(),
            request.firstName(),
            request.lastName(),
            request.email(),
            request.phone()
        );

        CustomerSnapshot customer = updateCustomerProfile.updateCustomerProfile(command);

        return ResponseEntity.status(HttpStatus.CREATED).body(CustomerResponse.from(customer));
    }

}
