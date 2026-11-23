package com.example.notes;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

/**
 * Keyora settings, bound from the {@code keyora.*} properties, which in turn read the
 * {@code KEYORA_*} environment variables (see application.properties).
 *
 * @param url          where this application reaches Keyora
 * @param issuer       the {@code iss} value to require in tokens; defaults to {@code url}
 * @param clientId     the application's client ID, also the {@code aud} value to require
 * @param clientSecret the application's secret; server-side only
 */
@ConfigurationProperties("keyora")
public record KeyoraProperties(String url, String issuer, String clientId, String clientSecret) {

    public KeyoraProperties {
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(clientSecret)) {
            throw new IllegalStateException(
                    "KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh and load examples/.env)");
        }
        url = StringUtils.trimTrailingCharacter(url, '/');
        if (!StringUtils.hasText(issuer)) {
            issuer = url;
        }
    }

    public String jwkSetUri() {
        return url + "/.well-known/jwks.json";
    }
}
