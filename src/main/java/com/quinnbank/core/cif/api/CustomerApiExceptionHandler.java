package com.quinnbank.core.cif.api;

import com.quinnbank.core.cif.api.response.ApiErrorResponse;
import com.quinnbank.core.cif.domain.exception.CustomerClosedException;
import com.quinnbank.core.cif.domain.exception.CustomerNotFoundException;
import com.quinnbank.core.cif.domain.exception.DuplicateCustomerEmailException;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class CustomerApiExceptionHandler {
    @ExceptionHandler(CustomerNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> customerNotFound() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiErrorResponse.of("CUSTOMER_NOT_FOUND", "Customer was not found."));
    }

    @ExceptionHandler(DuplicateCustomerEmailException.class)
    public ResponseEntity<ApiErrorResponse> duplicateEmail() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiErrorResponse.of("CUSTOMER_EMAIL_EXISTS", "A customer with this email already exists."));
    }

    @ExceptionHandler(CustomerClosedException.class)
    public ResponseEntity<ApiErrorResponse> customerClosed() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiErrorResponse.of("CUSTOMER_CLOSED", "Closed customer profiles cannot be updated."));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> validation(MethodArgumentNotValidException exception) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError error : exception.getBindingResult().getFieldErrors()) {
            fieldErrors.putIfAbsent(error.getField(), "Invalid value.");
        }

        return ResponseEntity.badRequest().body(ApiErrorResponse.validation(fieldErrors));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiErrorResponse> constraintViolation() {
        return ResponseEntity.badRequest()
                .body(ApiErrorResponse.of("VALIDATION_FAILED", "The request contains invalid fields."));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> illegalArgument() {
        return ResponseEntity.badRequest()
                .body(ApiErrorResponse.of("INVALID_CUSTOMER_REQUEST", "The customer request is invalid."));
    }
}
