package com.quinnbank.core.identity.api;

import com.quinnbank.core.identity.api.request.LoginIdentityRequest;
import com.quinnbank.core.identity.api.request.RefreshTokenRequest;
import com.quinnbank.core.identity.api.request.RegisterIdentityRequest;
import com.quinnbank.core.identity.api.response.TokenPairResponse;
import com.quinnbank.core.identity.application.command.LoginIdentityCommand;
import com.quinnbank.core.identity.application.command.RefreshTokenCommand;
import com.quinnbank.core.identity.application.command.RegisterIdentityCommand;
import com.quinnbank.core.identity.application.result.IssuedTokenPair;
import com.quinnbank.core.identity.application.service.LoginIdentityService;
import com.quinnbank.core.identity.application.service.RefreshTokenService;
import com.quinnbank.core.identity.application.service.RegisterIdentityService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/identity")
public class IdentityAuthenticationController {
    private static final String UNKNOWN_SOURCE_ADDRESS = "unknown";
    private static final int MAX_SOURCE_ADDRESS_LENGTH = 64;

    private final RegisterIdentityService registerIdentityService;
    private final LoginIdentityService loginIdentityService;
    private final RefreshTokenService refreshTokenService;

    public IdentityAuthenticationController(
        RegisterIdentityService registerIdentityService,
        LoginIdentityService loginIdentityService,
        RefreshTokenService refreshTokenService
    ) {
        this.registerIdentityService = registerIdentityService;
        this.loginIdentityService = loginIdentityService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping(
        value = "/register",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<TokenPairResponse> register(
        @Valid 
        @RequestBody 
        RegisterIdentityRequest request,
        HttpServletRequest httpRequest
    ) {
        RegisterIdentityCommand command = new RegisterIdentityCommand(
            request.loginIdentifier(),
            request.password(),
            CorrelationIdFilter.getCorrelationId(httpRequest),
            sourceAddress(httpRequest)
        );

        IssuedTokenPair issuedTokenPair = registerIdentityService.register(command);
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .cacheControl(CacheControl.noStore())
            .body(TokenPairResponse.from(issuedTokenPair));
    }

    @PostMapping(
        value = "/login",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<TokenPairResponse> login(
        @Valid 
        @RequestBody 
        LoginIdentityRequest request,
        HttpServletRequest httpRequest
    ) {
        LoginIdentityCommand command = new LoginIdentityCommand(
            request.loginIdentifier(),
            request.password(),
            CorrelationIdFilter.getCorrelationId(httpRequest),
            sourceAddress(httpRequest)
        );

        IssuedTokenPair issuedTokenPair = loginIdentityService.login(command);
        return ResponseEntity
            .ok()
            .cacheControl(CacheControl.noStore())
            .body(TokenPairResponse.from(issuedTokenPair));
    }

    @PostMapping(
        value = "/refresh",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<TokenPairResponse> refresh(
        @Valid 
        @RequestBody 
        RefreshTokenRequest request,
        HttpServletRequest httpRequest
    ) {
        RefreshTokenCommand command = new RefreshTokenCommand(
            request.refreshToken(),
            CorrelationIdFilter.getCorrelationId(httpRequest),
            sourceAddress(httpRequest)
        );

        IssuedTokenPair issuedTokenPair = refreshTokenService.refresh(command);
        return ResponseEntity
            .ok()
            .cacheControl(CacheControl.noStore())
            .body(TokenPairResponse.from(issuedTokenPair));
    }

    private static String sourceAddress(HttpServletRequest request) {
        String sourceAddress = request.getRemoteAddr();
        if (sourceAddress == null || sourceAddress.isBlank() || sourceAddress.length() > MAX_SOURCE_ADDRESS_LENGTH) {
            return UNKNOWN_SOURCE_ADDRESS;
        }
        return sourceAddress;
    }
}
