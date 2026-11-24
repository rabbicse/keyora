package com.example.notes;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Local verification of Keyora access tokens, and the mapping from token claims to
 * Spring Security authorities.
 */
@Configuration
@EnableMethodSecurity // turns on @PreAuthorize, used in NotesController
public class SecurityConfig {

    /**
     * Endpoints that do not go through local JWT verification. /me/live is here because it
     * checks its token by introspection instead (AccountController).
     */
    private static final Set<String> NO_LOCAL_JWT =
            Set.of("/public", "/register", "/login", "/refresh", "/logout", "/me/live");

    /** Error code used by {@link #timestamps} so that expiry can be told apart from other failures. */
    private static final String TOKEN_EXPIRED = "token_expired";

    /**
     * Tolerance for clock differences between this machine and Keyora. Zero keeps the
     * example strict; a few seconds is reasonable in production. (Spring's own
     * JwtTimestampValidator defaults to 60 seconds, which is as long as the access tokens
     * the examples use.)
     */
    private static final Duration CLOCK_SKEW = Duration.ZERO;

    private final ObjectMapper json;

    public SecurityConfig(ObjectMapper json) {
        this.json = json;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationEntryPoint entryPoint = this::unauthorized;
        AccessDeniedHandler accessDenied = (request, response, e) ->
                writeError(response, HttpStatus.FORBIDDEN, "forbidden", "you do not have access to this resource");

        // The header is ignored on the endpoints that do not use local verification, so a
        // stale token sent along with POST /login or /refresh cannot cause a 401 there.
        DefaultBearerTokenResolver header = new DefaultBearerTokenResolver();
        BearerTokenResolver resolver = request ->
                NO_LOCAL_JWT.contains(request.getServletPath()) ? null : header.resolve(request);

        http
                // CSRF protection defends cookie-based sessions, where the browser attaches the
                // credential by itself. This API authenticates only with a bearer token that the
                // client must add to each request explicitly, so there is nothing for CSRF to abuse.
                .csrf(csrf -> csrf.disable())
                // No HTTP session: every request is authenticated by its token alone.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Spring Security's built-in logout filter claims POST /logout for session
                // logout. Turn it off so the request reaches AuthController, which revokes
                // the session in Keyora.
                .logout(logout -> logout.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(NO_LOCAL_JWT.toArray(String[]::new)).permitAll()
                        // Everything else needs a valid token. Permissions and roles are
                        // then checked per method with @PreAuthorize.
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenResolver(resolver)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDenied))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDenied))
                .addFilterBefore(new KeyoraUnavailableFilter(), BearerTokenAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Verifies access tokens with Keyora's public keys. All six checks from
     * examples/README.md are configured here:
     *
     * <ol>
     *   <li>algorithm pinned to RS256, whatever the token's header claims;</li>
     *   <li>signature, against the JWKS key whose {@code kid} matches (Nimbus fetches the
     *       key set on first use, caches it, and refetches on an unknown {@code kid});</li>
     *   <li>{@code exp} in the future;</li>
     *   <li>{@code iss} equal to the Keyora issuer;</li>
     *   <li>{@code aud} equal to this application's client ID;</li>
     *   <li>{@code token_use} equal to {@code access}.</li>
     * </ol>
     *
     * <p>The decoder is built from the JWKS URL directly. Spring's {@code issuer-uri}
     * setting would try OIDC discovery, and Keyora does not serve a discovery document.
     */
    @Bean
    JwtDecoder jwtDecoder(KeyoraProperties keyora) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(keyora.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        // setJwtValidator replaces Spring's defaults, so every claim check is listed here.
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                SecurityConfig::timestamps,
                new JwtIssuerValidator(keyora.issuer()),
                // Spring Security does not check the audience unless told to. Without this,
                // a token issued to any other application on the same Keyora would be accepted.
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(keyora.clientId())),
                // An OIDC ID token has the same issuer and audience as an access token:
                // only this claim keeps it from being accepted as an API credential.
                new JwtClaimValidator<Object>("token_use", "access"::equals)));
        return decoder;
    }

    /** Requires an unexpired {@code exp} and, when present, an {@code nbf} that has passed. */
    private static OAuth2TokenValidatorResult timestamps(Jwt jwt) {
        Instant now = Instant.now();
        Instant expiresAt = jwt.getExpiresAt();
        if (expiresAt == null) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "the token has no exp claim", null));
        }
        if (now.isAfter(expiresAt.plus(CLOCK_SKEW))) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(TOKEN_EXPIRED, "the access token has expired", null));
        }
        Instant notBefore = jwt.getNotBefore();
        if (notBefore != null && now.isBefore(notBefore.minus(CLOCK_SKEW))) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "the token is not valid yet", null));
        }
        return OAuth2TokenValidatorResult.success();
    }

    /**
     * Maps Keyora's claims to authorities: each entry of {@code permissions} as it is
     * ({@code notes:read}, for {@code hasAuthority}) and each entry of {@code roles} with the
     * {@code ROLE_} prefix ({@code ROLE_editor}, for {@code hasRole}).
     */
    private static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            for (String permission : claimList(jwt, "permissions")) {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
            for (String role : claimList(jwt, "roles")) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            return authorities;
        });
        return converter;
    }

    private static List<String> claimList(Jwt jwt, String name) {
        List<String> values = jwt.getClaimAsStringList(name);
        return values == null ? List.of() : values;
    }

    /**
     * Answers every authentication failure with 401 and one of three codes:
     * no bearer token at all, an expired token, or a token that is invalid in any other way.
     */
    private void unauthorized(HttpServletRequest request, HttpServletResponse response,
                              org.springframework.security.core.AuthenticationException e) throws IOException {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        if (!(e instanceof OAuth2AuthenticationException)) {
            // Spring Security found no token to check (InsufficientAuthenticationException).
            writeError(response, HttpStatus.UNAUTHORIZED, "missing_token", "a bearer access token is required");
        } else if (expiredOnly(e)) {
            writeError(response, HttpStatus.UNAUTHORIZED, TOKEN_EXPIRED, "the access token has expired");
        } else {
            // Deliberately vague: do not tell the caller which check failed.
            writeError(response, HttpStatus.UNAUTHORIZED, "invalid_token", "the access token is invalid");
        }
    }

    /**
     * True when the signature verified and expiry was the only claim check that failed.
     * A token that is expired and also has, say, the wrong audience is reported as invalid.
     */
    private static boolean expiredOnly(Exception e) {
        return e.getCause() instanceof JwtValidationException validation
                && validation.getErrors().stream().allMatch(error -> TOKEN_EXPIRED.equals(error.getErrorCode()));
    }

    private void writeError(HttpServletResponse response, HttpStatus status, String code, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        json.writeValue(response.getOutputStream(), ApiError.of(code, message));
    }

    /**
     * When the JWKS cannot be fetched (Keyora down or unreachable) the token can be neither
     * accepted nor called invalid. Spring Security signals this with an
     * AuthenticationServiceException, which would otherwise surface as a plain 500.
     */
    private final class KeyoraUnavailableFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            try {
                chain.doFilter(request, response);
            } catch (AuthenticationServiceException e) {
                logger.warn("could not verify a token: " + e.getMessage());
                writeError(response, HttpStatus.BAD_GATEWAY, "identity_unavailable", "the identity service is unavailable");
            }
        }
    }
}
