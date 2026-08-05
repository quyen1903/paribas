package com.quinnbank.core.identity.infrastructure.configuration;

import com.quinnbank.core.identity.api.CorrelationIdFilter;
import com.quinnbank.core.identity.application.policy.AuthenticationPolicy;
import com.quinnbank.core.identity.application.policy.RegistrationPasswordPolicy;
import com.quinnbank.core.identity.application.port.AuthenticationSessionRepository;
import com.quinnbank.core.identity.application.port.AuthenticationThrottle;
import com.quinnbank.core.identity.application.port.IdentityAccountRepository;
import com.quinnbank.core.identity.application.port.JwtSigningKeyRepository;
import com.quinnbank.core.identity.application.port.PasswordService;
import com.quinnbank.core.identity.application.port.TokenPairService;
import com.quinnbank.core.identity.infrastructure.security.DatabaseBackedJwtTokenService;
import com.quinnbank.core.identity.infrastructure.security.DatabaseJwkSource;
import com.quinnbank.core.identity.infrastructure.security.ExternalRsaSigningKeyMaterialProvider;
import com.quinnbank.core.identity.infrastructure.security.IdentityJwtClaimValidator;
import com.quinnbank.core.identity.infrastructure.security.IdentityJwtDecoderFactory;
import com.quinnbank.core.identity.infrastructure.security.InMemoryAuthenticationThrottle;
import com.quinnbank.core.identity.infrastructure.security.SpringPasswordService;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.ResourceLoader;
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
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(IdentityAuthenticationProperties.class)
public class IdentitySecurityConfiguration {
    private static final String REGISTER_PATH = "/api/v1/identity/register";
    private static final String LOGIN_PATH = "/api/v1/identity/login";
    private static final String REFRESH_PATH = "/api/v1/identity/refresh";

    @Bean
    public SecurityFilterChain identityApiSecurityFilterChain(
            HttpSecurity http,
            JwtDecoder accessTokenDecoder
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
                        .requestMatchers(HttpMethod.POST, REGISTER_PATH, LOGIN_PATH, REFRESH_PATH).permitAll()
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
                        .accessDeniedHandler(this::writeForbidden)
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
            ExternalRsaSigningKeyMaterialProvider signingMaterialProvider,
            Clock clock
    ) {
        return new DatabaseJwkSource(signingKeys, signingMaterialProvider, clock);
    }

    @Bean
    public ExternalRsaSigningKeyMaterialProvider rsaSigningKeyMaterialProvider(
            IdentityAuthenticationProperties properties,
            ResourceLoader resourceLoader
    ) {
        return new ExternalRsaSigningKeyMaterialProvider(properties, resourceLoader);
    }

    @Bean
    public TokenPairService tokenPairService(
            JwtSigningKeyRepository signingKeys,
            ExternalRsaSigningKeyMaterialProvider signingMaterialProvider,
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
                signingMaterialProvider,
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
            Exception exception
    ) throws IOException {
        writeSecurityError(response, request, HttpServletResponse.SC_FORBIDDEN,
                "ACCESS_DENIED", "The authenticated identity is not allowed to perform this action.");
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
