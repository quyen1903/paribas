package com.quinnbank.core.web;

import jakarta.servlet.http.HttpServletRequest;

import java.util.regex.Pattern;

public final class CorrelationIdContext {
    public static final String REQUEST_ATTRIBUTE = CorrelationIdContext.class.getName() + ".correlationId";
    private static final Pattern VALID_CORRELATION_ID =
        Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,63}");

    private CorrelationIdContext() {
    }

    public static String get(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ATTRIBUTE);
        if (value instanceof String correlationId && VALID_CORRELATION_ID.matcher(correlationId).matches()) {
            return correlationId;
        }
        throw new IllegalStateException("A validated correlation id is required.");
    }
}
