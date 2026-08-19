package com.quinnbank.core.identity.api;

import com.quinnbank.core.web.CorrelationIdContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.UUID;
import java.util.regex.Pattern;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {
    public static final String HEADER_NAME = "X-Correlation-Id";
    public static final String REQUEST_ATTRIBUTE = CorrelationIdContext.REQUEST_ATTRIBUTE;

    private static final int MAX_CORRELATION_ID_LENGTH = 64;
    private static final Pattern VALID_CORRELATION_ID =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0," + (MAX_CORRELATION_ID_LENGTH - 1) + "}");

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        String correlationId = acceptedCorrelationId(singleHeaderValue(request));
        request.setAttribute(REQUEST_ATTRIBUTE, correlationId);
        response.setHeader(HEADER_NAME, correlationId);
        filterChain.doFilter(request, response);
    }

    private static String singleHeaderValue(HttpServletRequest request) {
        Enumeration<String> values = request.getHeaders(HEADER_NAME);
        if (values == null || !values.hasMoreElements()) {
            return null;
        }

        String value = values.nextElement();
        return values.hasMoreElements() ? null : value;
    }

    public static String getCorrelationId(HttpServletRequest request) {
        return CorrelationIdContext.get(request);
    }

    static String acceptedCorrelationId(String candidate) {
        if (candidate != null && VALID_CORRELATION_ID.matcher(candidate).matches()) {
            return candidate;
        }
        return UUID.randomUUID().toString();
    }
}
