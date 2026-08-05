package com.quinnbank.core.identity.infrastructure.security;

import com.quinnbank.core.identity.application.exception.SigningKeyUnavailableException;
import com.quinnbank.core.identity.infrastructure.configuration.IdentityAuthenticationProperties;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public class ExternalRsaSigningKeyMaterialProvider {
    private static final Pattern KEY_ID_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,99}");
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("[0-9a-f]{64}");

    private final IdentityAuthenticationProperties properties;
    private final ResourceLoader resourceLoader;

    private volatile RsaSigningKeyMaterial cachedSigningMaterial;
    private volatile Set<String> cachedTrustedFingerprints;

    public ExternalRsaSigningKeyMaterialProvider(
            IdentityAuthenticationProperties properties,
            ResourceLoader resourceLoader
    ) {
        this.properties = properties;
        this.resourceLoader = resourceLoader;
    }

    public RsaSigningKeyMaterial currentSigningKey() {
        RsaSigningKeyMaterial current = cachedSigningMaterial;
        if (current != null) {
            return current;
        }

        synchronized (this) {
            if (cachedSigningMaterial == null) {
                cachedSigningMaterial = loadSigningMaterial();
            }
            return cachedSigningMaterial;
        }
    }

    public Set<String> trustedPublicKeyFingerprints() {
        Set<String> current = cachedTrustedFingerprints;
        if (current != null) {
            return current;
        }

        synchronized (this) {
            if (cachedTrustedFingerprints == null) {
                cachedTrustedFingerprints = Collections.unmodifiableSet(loadTrustedFingerprints());
            }
            return cachedTrustedFingerprints;
        }
    }

    private RsaSigningKeyMaterial loadSigningMaterial() {
        try {
            String keyId = requiredKeyId(properties.getSigningKeyId());
            RSAPublicKey publicKey = loadPublicKey(requiredPublicLocation());
            RSAPrivateKey privateKey = loadPrivateKey(requiredPrivateLocation());
            if (!publicKey.getModulus().equals(privateKey.getModulus())) {
                throw new GeneralSecurityException("RSA public/private key mismatch.");
            }
            RsaPublicKeyCodec.requireSupportedStrength(publicKey);
            if (privateKey.getModulus().bitLength() < RsaPublicKeyCodec.MINIMUM_RSA_BITS
                    || privateKey.getModulus().bitLength() > RsaPublicKeyCodec.MAXIMUM_RSA_BITS) {
                throw new GeneralSecurityException("RSA private key strength is outside the supported range.");
            }
            return new RsaSigningKeyMaterial(
                    keyId,
                    publicKey,
                    privateKey,
                    RsaPublicKeyCodec.sha256(publicKey)
            );
        } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
            throw new SigningKeyUnavailableException();
        }
    }

    private Set<String> loadTrustedFingerprints() {
        try {
            Set<String> fingerprints = parseConfiguredFingerprints(properties.getTrustedPublicKeySha256());
            String publicKeyLocation = properties.getPublicKeyLocation();
            if (publicKeyLocation != null && !publicKeyLocation.isBlank()) {
                fingerprints.add(RsaPublicKeyCodec.sha256(loadPublicKey(publicKeyLocation.trim())));
            }
            if (fingerprints.isEmpty()) {
                throw new SigningKeyUnavailableException();
            }
            return fingerprints;
        } catch (IOException | GeneralSecurityException | IllegalArgumentException exception) {
            throw new SigningKeyUnavailableException();
        }
    }

    private RSAPublicKey loadPublicKey(String location) throws IOException {
        Resource resource = safeResource(location, true);
        try (InputStream inputStream = resource.getInputStream()) {
            RSAPublicKey key = RsaKeyConverters.x509().convert(inputStream);
            if (key == null) {
                throw new IOException("Public key conversion failed.");
            }
            return key;
        }
    }

    private RSAPrivateKey loadPrivateKey(String location) throws IOException {
        Resource resource = safeResource(location, false);
        try (InputStream inputStream = resource.getInputStream()) {
            RSAPrivateKey key = RsaKeyConverters.pkcs8().convert(inputStream);
            if (key == null) {
                throw new IOException("Private key conversion failed.");
            }
            return key;
        }
    }

    private Resource safeResource(String location, boolean allowClasspath) throws IOException {
        String normalized = location.trim();
        boolean allowed = normalized.startsWith("file:")
                || (allowClasspath && normalized.startsWith("classpath:"));
        if (!allowed || normalized.startsWith("http:") || normalized.startsWith("https:")) {
            throw new IOException("Key resource scheme is not allowed.");
        }
        Resource resource = resourceLoader.getResource(normalized);
        if (!resource.exists() || !resource.isReadable()) {
            throw new IOException("Key resource is unavailable.");
        }
        return resource;
    }

    private String requiredPublicLocation() {
        String value = properties.getPublicKeyLocation();
        if (value == null || value.isBlank()) {
            throw new SigningKeyUnavailableException();
        }
        return value.trim();
    }

    private String requiredPrivateLocation() {
        String value = properties.getPrivateKeyLocation();
        if (value == null || value.isBlank()) {
            throw new SigningKeyUnavailableException();
        }
        return value.trim();
    }

    private static String requiredKeyId(String value) {
        if (value == null || !KEY_ID_PATTERN.matcher(value.trim()).matches()) {
            throw new SigningKeyUnavailableException();
        }
        return value.trim();
    }

    private static Set<String> parseConfiguredFingerprints(String configured) {
        Set<String> fingerprints = new HashSet<>();
        if (configured == null || configured.isBlank()) {
            return fingerprints;
        }

        for (String candidate : configured.split(",")) {
            String normalized = candidate.trim().toLowerCase(Locale.ROOT);
            if (!FINGERPRINT_PATTERN.matcher(normalized).matches()) {
                throw new SigningKeyUnavailableException();
            }
            fingerprints.add(normalized);
        }
        return fingerprints;
    }
}
