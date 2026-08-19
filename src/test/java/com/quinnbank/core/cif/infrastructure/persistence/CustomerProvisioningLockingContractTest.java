package com.quinnbank.core.cif.infrastructure.persistence;

import jakarta.persistence.LockModeType;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.lang.reflect.Method;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CustomerProvisioningLockingContractTest {
    @Test
    void customerEligibilityReadUsesAPessimisticWriteLock() throws Exception {
        Method method = SpringDataCustomerRepository.class.getDeclaredMethod(
            "findByIdForUpdate",
            UUID.class
        );

        Lock lock = method.getAnnotation(Lock.class);
        Query query = method.getAnnotation(Query.class);
        assertNotNull(lock);
        assertNotNull(query);
        assertEquals(LockModeType.PESSIMISTIC_WRITE, lock.value());
        assertEquals(
            "select customer from Customer customer where customer.id = :customerId",
            query.value()
        );
    }
}
