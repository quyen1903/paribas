package com.quinnbank.core.identity.infrastructure.configuration;

import com.quinnbank.core.identity.api.CorrelationIdFilter;
import com.quinnbank.core.identity.application.policy.AuthenticationPolicy;
import com.quinnbank.core.identity.application.policy.RegistrationPasswordPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.AuthenticationThrottle;
import com.quinnbank.core.identity.application.port.AuthorizationDenialAudit;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.application.port.PasswordService;
import com.quinnbank.core.identity.application.port.TokenPairService;
import com.quinnbank.core.identity.application.result.IdentitySubjectType;
import com.quinnbank.core.identity.infrastructure.security.DatabaseBackedJwtTokenService;
import com.quinnbank.core.identity.infrastructure.security.DatabaseJwkSource;
import com.quinnbank.core.identity.infrastructure.security.IdentityJwtClaimValidator;
import com.quinnbank.core.identity.infrastructure.security.IdentityJwtDecoderFactory;
import com.quinnbank.core.identity.infrastructure.security.InMemoryAuthenticationThrottle;
import com.quinnbank.core.identity.infrastructure.security.JdkRsaSigningKeyMaterialGenerator;
import com.quinnbank.core.identity.infrastructure.security.RsaSigningKeyMaterialGenerator;
import com.quinnbank.core.identity.infrastructure.security.SpringPasswordService;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(IdentityAuthenticationProperties.class)
public class IdentitySecurityConfiguration {
    private static final String LOGIN_PATH = "/api/v1/identity/login";
    private static final String REFRESH_PATH = "/api/v1/identity/refresh";

    @Bean
    public SecurityFilterChain identityApiSecurityFilterChain(
        HttpSecurity http,
        JwtDecoder accessTokenDecoder,
        AuthorizationDenialAudit authorizationDenials
    ) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .requestCache(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                .requestMatchers(HttpMethod.POST, LOGIN_PATH, REFRESH_PATH).permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .authenticationEntryPoint(this::writeUnauthorized)
                .jwt(jwt -> jwt
                        .decoder(accessTokenDecoder)
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(this::writeUnauthorized)
                .accessDeniedHandler((request, response, exception) ->
                    writeForbidden(request, response, authorizationDenials))
            )
            .build();
    }

    @Bean
    public JwtDecoder accessTokenDecoder(
        DatabaseJwkSource jwkSource,
        IdentityAuthenticationProperties properties,
        IdentityAccountRepository identityAccounts,
        AuthenticationSessionRepository sessions,
        JwtSigningKeyRepository signingKeys,
        Clock clock
    ) {
        return IdentityJwtDecoderFactory.accessTokenDecoder(
            jwkSource,
            properties,
            identityAccounts,
            sessions,
            signingKeys,
            clock
        );
    }

    @Bean
    public DatabaseJwkSource databaseJwkSource(
        JwtSigningKeyRepository signingKeys,
        Clock clock,
        IdentityAuthenticationProperties properties
    ) {
        return new DatabaseJwkSource(signingKeys, clock, properties.getClockSkew());
    }

    @Bean
    public RsaSigningKeyMaterialGenerator rsaSigningKeyMaterialGenerator() {
        return new JdkRsaSigningKeyMaterialGenerator();
    }

    @Bean
    public TokenPairService tokenPairService(
        JwtSigningKeyRepository signingKeys,
        RsaSigningKeyMaterialGenerator signingMaterialGenerator,
        DatabaseJwkSource jwkSource,
        IdentityAuthenticationProperties properties,
        Clock clock
    ) {
        validateTokenLifetimes(properties);
        JwtDecoder refreshDecoder = IdentityJwtDecoderFactory.refreshTokenDecoder(
            jwkSource,
            properties,
            signingKeys,
            clock
        );
        return new DatabaseBackedJwtTokenService(
            signingKeys,
            signingMaterialGenerator,
            properties,
            refreshDecoder
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder(IdentityAuthenticationProperties properties) {
        int strength = properties.getBcryptStrength();
        if (strength < 10 || strength > 16) {
            throw new IllegalArgumentException("bcryptStrength must be between 10 and 16.");
        }
        return new BCryptPasswordEncoder(strength);
    }

    @Bean
    public PasswordService passwordService(PasswordEncoder passwordEncoder) {
        return new SpringPasswordService(passwordEncoder);
    }

    @Bean
    public AuthenticationPolicy authenticationPolicy(IdentityAuthenticationProperties properties) {
        return new AuthenticationPolicy(
            properties.getLoginLockThreshold(),
            properties.getLoginLockDuration(),
            properties.getRefreshTokenTtl()
        );
    }

    @Bean
    public RegistrationPasswordPolicy registrationPasswordPolicy() {
        return new RegistrationPasswordPolicy();
    }

    @Bean
    public AuthenticationThrottle authenticationThrottle(IdentityAuthenticationProperties properties) {
        return new InMemoryAuthenticationThrottle(
            properties.getRegistrationLimitPerMinute(),
            properties.getLoginSourceLimitPerMinute(),
            properties.getLoginIdentifierLimitPerMinute(),
            properties.getRefreshLimitPerMinute()
        );
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(actorTypeAuthorityConverter());
        return converter;
    }

    private Converter<Jwt, Collection<GrantedAuthority>> actorTypeAuthorityConverter() {
        return jwt -> {
            String actorType = jwt.getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM);
            if (actorType == null || actorType.isBlank()) {
                return List.of();
            }
            return List.of(new SimpleGrantedAuthority("actor:" + actorType.toLowerCase(Locale.ROOT)));
        };
    }

    private void writeUnauthorized(
        HttpServletRequest request,
        HttpServletResponse response,
        Exception exception
    ) throws IOException {
        writeSecurityError(response, request, HttpServletResponse.SC_UNAUTHORIZED,
                "AUTHENTICATION_REQUIRED", "A valid access token is required.");
        response.setHeader("WWW-Authenticate", "Bearer");
    }

    private void writeForbidden(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthorizationDenialAudit authorizationDenials
    ) throws IOException {
        recordHttpAuthorizationDenial(request, authorizationDenials);
        writeSecurityError(response, request, HttpServletResponse.SC_FORBIDDEN,
                "ACCESS_DENIED", "The authenticated identity is not allowed to perform this action.");
    }

    private static void recordHttpAuthorizationDenial(
        HttpServletRequest request,
        AuthorizationDenialAudit authorizationDenials
    ) {
        String correlationId = CorrelationIdFilter.getCorrelationId(request);
        if (request.getUserPrincipal() instanceof JwtAuthenticationToken authentication) {
            UUID identityId;
            IdentitySubjectType actorType;
            try {
                identityId = UUID.fromString(authentication.getToken().getSubject());
                actorType = IdentitySubjectType.valueOf(
                    authentication.getToken().getClaimAsString(IdentityJwtClaimValidator.ACTOR_TYPE_CLAIM)
                );
            } catch (IllegalArgumentException exception) {
                // A validated JWT should have a known UUID subject and actor type. Audit the invalid context safely.
                authorizationDenials.recordAnonymous(
                    IdentitySubjectType.RETAIL_CUSTOMER,
                    "AUTHORIZATION_CONTEXT_INVALID",
                    correlationId
                );
                return;
            }
            authorizationDenials.recordKnown(
                identityId,
                actorType,
                "HTTP_ACCESS_POLICY_DENIED",
                correlationId
            );
            return;
        }
        authorizationDenials.recordAnonymous(
            IdentitySubjectType.RETAIL_CUSTOMER,
            "AUTHORIZATION_CONTEXT_INVALID",
            correlationId
        );
    }

    private static void writeSecurityError(
        HttpServletResponse response,
        HttpServletRequest request,
        int status,
        String code,
        String message
    ) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        Object attribute = request.getAttribute(CorrelationIdFilter.REQUEST_ATTRIBUTE);
        String correlationId = attribute instanceof String value ? value : "unavailable";
        response.getWriter().write(
                "{\"code\":\"" + code + "\",\"message\":\"" + message
                        + "\",\"correlationId\":\"" + correlationId + "\"}"
        );
    }

    private static void validateTokenLifetimes(IdentityAuthenticationProperties properties) {
        Duration accessTtl = properties.getAccessTokenTtl();
        Duration refreshTtl = properties.getRefreshTokenTtl();
        if (accessTtl == null || accessTtl.isNegative() || accessTtl.isZero()
                || accessTtl.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("accessTokenTtl must be positive and at most one hour.");
        }
        if (refreshTtl == null || refreshTtl.compareTo(accessTtl) <= 0
                || refreshTtl.compareTo(Duration.ofDays(90)) > 0) {
            throw new IllegalArgumentException(
                "refreshTokenTtl must exceed accessTokenTtl and be at most 90 days."
            );
        }
    }
}
