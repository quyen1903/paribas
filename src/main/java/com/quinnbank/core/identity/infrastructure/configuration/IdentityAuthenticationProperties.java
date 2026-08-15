package com.quinnbank.core.identity.infrastructure.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "quinnbank.identity.authentication")
public class IdentityAuthenticationProperties {
    private String issuer = "https://auth.quinnbank.example.invalid";
    private String accessAudience = "quinnbank-core-api";
    private String refreshAudience = "quinnbank-core-refresh";
    private Duration accessTokenTtl = Duration.ofMinutes(5);
    private Duration refreshTokenTtl = Duration.ofDays(7);
    private Duration clockSkew = Duration.ofSeconds(30);
    private int loginLockThreshold = 5;
    private Duration loginLockDuration = Duration.ofMinutes(15);
    private int bcryptStrength = 12;
    private int registrationLimitPerMinute = 5;
    private int loginSourceLimitPerMinute = 20;
    private int loginIdentifierLimitPerMinute = 10;
    private int refreshLimitPerMinute = 30;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAccessAudience() {
        return accessAudience;
    }

    public void setAccessAudience(String accessAudience) {
        this.accessAudience = accessAudience;
    }

    public String getRefreshAudience() {
        return refreshAudience;
    }

    public void setRefreshAudience(String refreshAudience) {
        this.refreshAudience = refreshAudience;
    }

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }

    public void setRefreshTokenTtl(Duration refreshTokenTtl) {
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public Duration getClockSkew() {
        return clockSkew;
    }

    public void setClockSkew(Duration clockSkew) {
        this.clockSkew = clockSkew;
    }

    public int getLoginLockThreshold() {
        return loginLockThreshold;
    }

    public void setLoginLockThreshold(int loginLockThreshold) {
        this.loginLockThreshold = loginLockThreshold;
    }

    public Duration getLoginLockDuration() {
        return loginLockDuration;
    }

    public void setLoginLockDuration(Duration loginLockDuration) {
        this.loginLockDuration = loginLockDuration;
    }

    public int getBcryptStrength() {
        return bcryptStrength;
    }

    public void setBcryptStrength(int bcryptStrength) {
        this.bcryptStrength = bcryptStrength;
    }

    public int getRegistrationLimitPerMinute() {
        return registrationLimitPerMinute;
    }

    public void setRegistrationLimitPerMinute(int registrationLimitPerMinute) {
        this.registrationLimitPerMinute = registrationLimitPerMinute;
    }

    public int getLoginSourceLimitPerMinute() {
        return loginSourceLimitPerMinute;
    }

    public void setLoginSourceLimitPerMinute(int loginSourceLimitPerMinute) {
        this.loginSourceLimitPerMinute = loginSourceLimitPerMinute;
    }

    public int getLoginIdentifierLimitPerMinute() {
        return loginIdentifierLimitPerMinute;
    }

    public void setLoginIdentifierLimitPerMinute(int loginIdentifierLimitPerMinute) {
        this.loginIdentifierLimitPerMinute = loginIdentifierLimitPerMinute;
    }

    public int getRefreshLimitPerMinute() {
        return refreshLimitPerMinute;
    }

    public void setRefreshLimitPerMinute(int refreshLimitPerMinute) {
        this.refreshLimitPerMinute = refreshLimitPerMinute;
    }
}
