package com.quinnbank.core.cif.api;

import com.quinnbank.core.cif.api.request.RegisterCustomerRequest;
import com.quinnbank.core.cif.api.request.UpdateCustomerRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.reflect.Method;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CustomerControllerAuthorizationContractTest {
    private static final String CIF_WRITE_POLICY = "hasAuthority('cif:write')";
    private static final String RETAIL_CUSTOMER_POLICY = "hasAuthority('actor:retail_customer')";

    @Test
    void everyCustomerMutationRequiresCifWriteAuthority() throws Exception {
        assertPolicy(CustomerController.class.getDeclaredMethod("register", RegisterCustomerRequest.class));
        assertPolicy(CustomerController.class.getDeclaredMethod("update", UpdateCustomerRequest.class));
        assertPolicy(CustomerController.class.getDeclaredMethod("close", UUID.class));
    }

    @Test
    void currentCustomerReadRequiresARetailCustomerActor() throws Exception {
        Method method = CurrentCustomerController.class.getDeclaredMethod(
            "getCurrent",
            HttpServletRequest.class
        );

        assertEquals(RETAIL_CUSTOMER_POLICY, method.getAnnotation(PreAuthorize.class).value());
    }

    private static void assertPolicy(Method method) {
        assertEquals(CIF_WRITE_POLICY, method.getAnnotation(PreAuthorize.class).value());
    }
}
