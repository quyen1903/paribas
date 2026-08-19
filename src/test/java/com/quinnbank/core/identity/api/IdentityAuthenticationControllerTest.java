package com.quinnbank.core.identity.api;

import com.quinnbank.core.identity.api.request.LoginIdentityRequest;
import com.quinnbank.core.identity.api.request.RefreshTokenRequest;
import com.quinnbank.core.identity.api.response.TokenPairResponse;
import com.quinnbank.core.identity.application.command.LoginIdentityCommand;
import com.quinnbank.core.identity.application.command.RefreshTokenCommand;
import com.quinnbank.core.identity.application.exception.AuthenticationRateLimitExceededException;
import com.quinnbank.core.identity.application.exception.InvalidCredentialsException;
import com.quinnbank.core.identity.application.exception.InvalidRefreshTokenException;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.service.LoginIdentityService;
import com.quinnbank.core.identity.application.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

class IdentityAuthenticationControllerTest {
    private static final String CORRELATION_ID = "api-test-correlation-01";
    private static final String LOGIN_IDENTIFIER = "api-user@example.invalid";
    private static final String RAW_PASSWORD = "synthetic-login-password";
    private static final String ACCESS_TOKEN = "synthetic.access.token";
    private static final String REFRESH_TOKEN = "synthetic.refresh.token";

    private LoginIdentityService loginIdentityService;
    private RefreshTokenService refreshTokenService;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        loginIdentityService = mock(LoginIdentityService.class);
        refreshTokenService = mock(RefreshTokenService.class);

        IdentityAuthenticationController controller = new IdentityAuthenticationController(
                loginIdentityService,
                refreshTokenService
        );
        mockMvc = standaloneSetup(controller)
                .setControllerAdvice(new IdentityApiExceptionHandler())
                .addFilters(new CorrelationIdFilter())
                .build();
    }

    @Test
    void loginReturnsSafeInvalidCredentialsError() throws Exception {
        when(loginIdentityService.login(any())).thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/v1/identity/login")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "loginIdentifier": "api-user@example.invalid",
                                  "password": "synthetic-login-password"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("The login identifier or password is invalid."))
                .andExpect(jsonPath("$.correlationId").value(CORRELATION_ID))
                .andExpect(content().string(not(containsString(LOGIN_IDENTIFIER))))
                .andExpect(content().string(not(containsString(RAW_PASSWORD))));
    }

    @Test
    void loginAndRefreshReturnOkTokenPairs() throws Exception {
        IssuedTokenPair issuedTokenPair = issuedTokenPair(UUID.randomUUID());
        when(loginIdentityService.login(any())).thenReturn(issuedTokenPair);
        when(refreshTokenService.refresh(any())).thenReturn(issuedTokenPair);

        mockMvc.perform(post("/api/v1/identity/login")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody()))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));

        mockMvc.perform(post("/api/v1/identity/refresh")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .with(request -> {
                            request.setRemoteAddr("2001:db8::10");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshBody()))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.accessToken").value(ACCESS_TOKEN))
                .andExpect(jsonPath("$.refreshToken").value(REFRESH_TOKEN));

        ArgumentCaptor<RefreshTokenCommand> commandCaptor = ArgumentCaptor.forClass(RefreshTokenCommand.class);
        verify(refreshTokenService).refresh(commandCaptor.capture());
        assertAll(
                () -> assertEquals(REFRESH_TOKEN, commandCaptor.getValue().refreshToken()),
                () -> assertEquals(CORRELATION_ID, commandCaptor.getValue().correlationId()),
                () -> assertEquals("2001:db8::10", commandCaptor.getValue().sourceAddress())
        );
    }

    @Test
    void refreshRejectsBlankTokenBeforeCallingApplicationService() throws Exception {
        mockMvc.perform(post("/api/v1/identity/refresh")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken": ""}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.correlationId").value(CORRELATION_ID))
                .andExpect(jsonPath("$.fieldErrors.refreshToken").value("Invalid value."));

        verify(refreshTokenService, never()).refresh(any());
    }

    @Test
    void applicationFailuresUseStableStatusCodesAndSafeMessages() throws Exception {
        when(loginIdentityService.login(any())).thenThrow(new AuthenticationRateLimitExceededException());
        when(refreshTokenService.refresh(any())).thenThrow(new InvalidRefreshTokenException());

        expectError(
                "/api/v1/identity/login",
                loginBody(),
                429,
                "AUTHENTICATION_RATE_LIMIT_EXCEEDED",
                "Too many authentication attempts. Try again later."
        );
        expectError(
                "/api/v1/identity/refresh",
                refreshBody(),
                401,
                "INVALID_REFRESH_TOKEN",
                "The refresh token is invalid or expired."
        );
    }

    @Test
    void invalidCorrelationIdIsNotEchoed() throws Exception {
        when(loginIdentityService.login(any())).thenReturn(issuedTokenPair(UUID.randomUUID()));

        mockMvc.perform(post("/api/v1/identity/login")
                        .header(CorrelationIdFilter.HEADER_NAME, "invalid correlation id")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody()))
                .andExpect(status().isOk())
                .andExpect(header().string(
                        CorrelationIdFilter.HEADER_NAME,
                        matchesPattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                ))
                .andExpect(header().string(
                        CorrelationIdFilter.HEADER_NAME,
                        not("invalid correlation id")
                ));

        ArgumentCaptor<LoginIdentityCommand> commandCaptor = ArgumentCaptor.forClass(LoginIdentityCommand.class);
        verify(loginIdentityService).login(commandCaptor.capture());
        assertFalse(commandCaptor.getValue().correlationId().contains(" "));
    }

    @Test
    void authenticationDtosRedactSecretsFromToString() {
        UUID identityId = UUID.randomUUID();
        LoginIdentityRequest loginRequest = new LoginIdentityRequest(LOGIN_IDENTIFIER, RAW_PASSWORD);
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest(REFRESH_TOKEN);
        TokenPairResponse response = TokenPairResponse.from(issuedTokenPair(identityId));

        assertAll(
                () -> assertFalse(loginRequest.toString().contains(LOGIN_IDENTIFIER)),
                () -> assertFalse(loginRequest.toString().contains(RAW_PASSWORD)),
                () -> assertFalse(refreshRequest.toString().contains(REFRESH_TOKEN)),
                () -> assertFalse(response.toString().contains(identityId.toString())),
                () -> assertFalse(response.toString().contains(ACCESS_TOKEN)),
                () -> assertFalse(response.toString().contains(REFRESH_TOKEN))
        );
    }

    private void expectError(
            String path,
            String body,
            int expectedStatus,
            String expectedCode,
            String expectedMessage
    ) throws Exception {
        mockMvc.perform(post(path)
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().is(expectedStatus))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.code").value(expectedCode))
                .andExpect(jsonPath("$.message").value(expectedMessage))
                .andExpect(jsonPath("$.correlationId").value(CORRELATION_ID))
                .andExpect(content().string(not(containsString("must not be exposed"))))
                .andExpect(content().string(not(containsString("already exists"))))
                .andExpect(content().string(not(containsString(RAW_PASSWORD))))
                .andExpect(content().string(not(containsString(REFRESH_TOKEN))));
    }

    private static IssuedTokenPair issuedTokenPair(UUID identityId) {
        return new IssuedTokenPair(
                identityId,
                ACCESS_TOKEN,
                Instant.parse("2030-01-01T00:05:00Z"),
                REFRESH_TOKEN,
                Instant.parse("2030-01-08T00:00:00Z")
        );
    }

    private static String loginBody() {
        return """
                {
                  "loginIdentifier": "api-user@example.invalid",
                  "password": "synthetic-login-password"
                }
                """;
    }

    private static String refreshBody() {
        return """
                {"refreshToken": "synthetic.refresh.token"}
                """;
    }
}
