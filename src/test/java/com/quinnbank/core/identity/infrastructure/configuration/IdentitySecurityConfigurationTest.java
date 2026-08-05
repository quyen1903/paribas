package com.quinnbank.core.identity.infrastructure.configuration;

import com.quinnbank.core.identity.api.CorrelationIdFilter;
import com.quinnbank.core.identity.api.IdentityAuthenticationController;
import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.service.LoginIdentityService;
import com.quinnbank.core.identity.application.service.RefreshTokenService;
import com.quinnbank.core.identity.application.service.RegisterIdentityService;
import com.quinnbank.core.identity.domain.AuthenticationActor;
import com.quinnbank.core.identity.domain.AuthenticationSession;
import com.quinnbank.core.identity.domain.EncodedPassword;
import com.quinnbank.core.identity.domain.IdentityAccount;
import com.quinnbank.core.identity.domain.JwtSigningKey;
import com.quinnbank.core.identity.domain.enums.IdentityActorType;
import com.quinnbank.core.identity.infrastructure.security.IdentityJwtClaimValidator;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotatedBeanDefinitionReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup;

class IdentitySecurityConfigurationTest {
    private static final Instant NOW = Instant.parse("2026-08-04T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String KEY_ID = "security-chain-test-key";
    private static final String ISSUER = "https://auth.quinnbank.example.invalid";
    private static final String ACCESS_AUDIENCE = "quinnbank-core-api";
    private static final String REFRESH_AUDIENCE = "quinnbank-core-refresh";
    private static final UUID IDENTITY_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID SESSION_ID = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final UUID REFRESH_TOKEN_ID = UUID.fromString("30000000-0000-0000-0000-000000000003");
    private static final String CORRELATION_ID = "security-chain-test-correlation";
    private static final String ENCODED_PASSWORD = "$2b$12$" + "b".repeat(53);

    private static RSAPublicKey publicKey;
    private static RSAPrivateKey privateKey;
    private static String publicKeyFingerprint;

    private GenericWebApplicationContext applicationContext;
    private MockMvc mockMvc;
    private RegisterIdentityService registerIdentityService;
    private LoginIdentityService loginIdentityService;
    private RefreshTokenService refreshTokenService;

    @BeforeAll
    static void generateEphemeralSigningKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3_072);
        KeyPair keyPair = generator.generateKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKeyFingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded())
        );
    }

    @BeforeEach
    void setUp() {
        registerIdentityService = mock(RegisterIdentityService.class);
        loginIdentityService = mock(LoginIdentityService.class);
        refreshTokenService = mock(RefreshTokenService.class);
        IdentityAccountRepository identityAccounts = mock(IdentityAccountRepository.class);
        AuthenticationSessionRepository sessions = mock(AuthenticationSessionRepository.class);
        JwtSigningKeyRepository signingKeys = mock(JwtSigningKeyRepository.class);

        IdentityAccount identity = activeIdentity();
        AuthenticationSession session = AuthenticationSession.open(
                SESSION_ID,
                IDENTITY_ID,
                REFRESH_TOKEN_ID,
                NOW.plusSeconds(3_600),
                NOW.minusSeconds(10)
        );
        JwtSigningKey signingKey = JwtSigningKey.register(
                KEY_ID,
                publicKey.getEncoded(),
                publicKeyFingerprint,
                NOW.minusSeconds(10)
        );
        when(identityAccounts.findById(IDENTITY_ID)).thenReturn(Optional.of(identity));
        when(sessions.findById(SESSION_ID)).thenReturn(Optional.of(session));
        when(signingKeys.findByKeyId(KEY_ID)).thenReturn(Optional.of(signingKey));

        applicationContext = new GenericWebApplicationContext();
        applicationContext.setServletContext(new MockServletContext());
        applicationContext.getEnvironment().getPropertySources().addFirst(new MapPropertySource(
                "identity-security-test",
                Map.of("quinnbank.identity.authentication.trusted-public-key-sha256", publicKeyFingerprint)
        ));
        applicationContext.registerBean("testClock", Clock.class, () -> CLOCK);
        applicationContext.registerBean("identityAccounts", IdentityAccountRepository.class, () -> identityAccounts);
        applicationContext.registerBean(
                "authenticationSessions",
                AuthenticationSessionRepository.class,
                () -> sessions
        );
        applicationContext.registerBean("jwtSigningKeys", JwtSigningKeyRepository.class, () -> signingKeys);
        applicationContext.registerBean(
                "registerIdentityService",
                RegisterIdentityService.class,
                () -> registerIdentityService
        );
        applicationContext.registerBean("loginIdentityService", LoginIdentityService.class, () -> loginIdentityService);
        applicationContext.registerBean(
                "refreshTokenService",
                RefreshTokenService.class,
                () -> refreshTokenService
        );
        new AnnotatedBeanDefinitionReader(applicationContext).register(
                TestWebConfiguration.class,
                IdentitySecurityConfiguration.class,
                CorrelationIdFilter.class
        );
        applicationContext.refresh();

        mockMvc = webAppContextSetup(applicationContext)
                .addFilters(
                        applicationContext.getBean(CorrelationIdFilter.class),
                        applicationContext.getBean("springSecurityFilterChain", jakarta.servlet.Filter.class)
                )
                .build();
    }

    @AfterEach
    void closeContext() {
        if (applicationContext != null) {
            applicationContext.close();
        }
    }

    @Test
    void onlyTheExactRegistrationLoginAndRefreshPostsArePublic() throws Exception {
        IssuedTokenPair pair = issuedTokenPair();
        when(registerIdentityService.register(any())).thenReturn(pair);
        when(loginIdentityService.login(any())).thenReturn(pair);
        when(refreshTokenService.refresh(any())).thenReturn(pair);

        mockMvc.perform(post("/api/v1/identity/register")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentialsBody()))
                .andExpect(status().isCreated());
        mockMvc.perform(post("/api/v1/identity/login")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(credentialsBody()))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/identity/refresh")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"synthetic.refresh.token\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/identity/register")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/identity/login")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/identity/refresh")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/identity/register/extra")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID))
                .andExpect(status().isUnauthorized());

        verify(registerIdentityService).register(any());
        verify(loginIdentityService).login(any());
        verify(refreshTokenService).refresh(any());
    }

    @Test
    void protectedEndpointRequiresBearerAuthentication() throws Exception {
        mockMvc.perform(get("/api/v1/security-test")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"))
                .andExpect(jsonPath("$.correlationId").value(CORRELATION_ID));
    }

    @Test
    void validAccessJwtIsAcceptedAndMapsOnlyTheActorAuthority() throws Exception {
        mockMvc.perform(get("/api/v1/security-test")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken())))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(IDENTITY_ID.toString())))
                .andExpect(content().string(containsString("actor:retail_customer")));
    }

    @Test
    void refreshJwtCannotAuthenticateAsAnAccessJwt() throws Exception {
        mockMvc.perform(get("/api/v1/security-test")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .header(HttpHeaders.AUTHORIZATION, bearer(refreshToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"));
    }

    @Test
    void authenticatedIdentityWithoutBusinessAuthorityReceivesForbidden() throws Exception {
        mockMvc.perform(delete("/api/v1/security-test/requires-cif-write")
                        .header(CorrelationIdFilter.HEADER_NAME, CORRELATION_ID)
                        .header(HttpHeaders.AUTHORIZATION, bearer(accessToken())))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"))
                .andExpect(jsonPath("$.correlationId").value(CORRELATION_ID));
    }

    private static IdentityAccount activeIdentity() {
        AuthenticationActor provisioningActor = AuthenticationActor.of(
                IdentityActorType.SERVICE_ACCOUNT,
                "synthetic-security-test"
        );
        IdentityAccount identity = IdentityAccount.provision(
                IDENTITY_ID,
                IDENTITY_ID,
                IdentityActorType.RETAIL_CUSTOMER,
                "security-chain-user@example.invalid",
                EncodedPassword.fromPasswordEncoder(ENCODED_PASSWORD),
                provisioningActor,
                CORRELATION_ID,
                NOW.minusSeconds(20)
        );
        identity.enable(provisioningActor, CORRELATION_ID, NOW.minusSeconds(19));
        identity.releaseAuditEvents();
        return identity;
    }

    private static IssuedTokenPair issuedTokenPair() {
        return new IssuedTokenPair(
                IDENTITY_ID,
                "synthetic.access.token",
                NOW.plusSeconds(300),
                "synthetic.refresh.token",
                NOW.plusSeconds(3_600)
        );
    }

    private static String accessToken() {
        return signedToken("at+jwt", ACCESS_AUDIENCE, IdentityJwtClaimValidator.ACCESS_TOKEN_USE);
    }

    private static String refreshToken() {
        return signedToken("rt+jwt", REFRESH_AUDIENCE, IdentityJwtClaimValidator.REFRESH_TOKEN_USE);
    }

    private static String signedToken(String type, String audience, String tokenUse) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(
                new RSAKey.Builder(publicKey)
                        .privateKey(privateKey)
                        .keyID(KEY_ID)
                        .build()
        )));
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(KEY_ID)
                .type(type)
                .build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(ISSUER)
                .subject(IDENTITY_ID.toString())
                .audience(List.of(audience))
                .issuedAt(NOW)
                .notBefore(NOW)
                .expiresAt(NOW.plusSeconds(300))
                .id(UUID.randomUUID().toString())
                .claim(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM, IdentityActorType.RETAIL_CUSTOMER.name())
                .claim(IdentityJwtClaimValidator.SESSION_ID_CLAIM, SESSION_ID.toString())
                .claim(IdentityJwtClaimValidator.TOKEN_USE_CLAIM, tokenUse)
                .build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private static String credentialsBody() {
        return """
                {
                  "loginIdentifier": "security-chain-user@example.invalid",
                  "password": "synthetic-login-password"
                }
                """;
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class TestWebConfiguration {
        @Bean
        IdentityAuthenticationController identityAuthenticationController(
                RegisterIdentityService registerIdentityService,
                LoginIdentityService loginIdentityService,
                RefreshTokenService refreshTokenService
        ) {
            return new IdentityAuthenticationController(
                    registerIdentityService,
                    loginIdentityService,
                    refreshTokenService
            );
        }

        @Bean
        SecurityTestController securityTestController() {
            return new SecurityTestController();
        }
    }

    @Controller
    static class SecurityTestController {
        @GetMapping(value = "/api/v1/security-test", produces = MediaType.TEXT_PLAIN_VALUE)
        @ResponseBody
        String authenticated(org.springframework.security.core.Authentication authentication) {
            return authentication.getName() + " " + authentication.getAuthorities();
        }

        @PreAuthorize("hasAuthority('cif:write')")
        @org.springframework.web.bind.annotation.DeleteMapping("/api/v1/security-test/requires-cif-write")
        @ResponseBody
        String requiresCifWrite() {
            return "not-reached";
        }
    }
}
