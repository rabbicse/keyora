package com.example.notes;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** The two ways to find out who is calling: from the token itself, or by asking Keyora. */
@RestController
public class AccountController {

    private final KeyoraClient keyora;

    public AccountController(KeyoraClient keyora) {
        this.keyora = keyora;
    }

    public record Me(String sub, String email, List<String> roles, List<String> permissions) {
    }

    /**
     * Local verification. By the time this method runs, Spring Security has verified the
     * token's signature, expiry, issuer and audience; no call to Keyora is made. The answer
     * is the snapshot inside the token, so a logout or role change shows up only when the
     * token expires or is refreshed.
     */
    @GetMapping("/me")
    Me me(@AuthenticationPrincipal Jwt jwt) {
        return new Me(jwt.getSubject(), jwt.getClaimAsString("email"),
                orEmpty(jwt.getClaimAsStringList("roles")), orEmpty(jwt.getClaimAsStringList("permissions")));
    }

    /**
     * Remote introspection. One network call per request, but it sees logouts, disabled
     * users and role changes immediately. This path is not behind the local JWT filter
     * (see SecurityConfig), so Keyora's answer is the only thing that decides.
     */
    @GetMapping("/me/live")
    Me live(@RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        String token = bearerToken(authorization);
        if (token == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "missing_token", "a bearer access token is required");
        }
        KeyoraClient.Introspection in = keyora.introspect(token);
        if (!in.active()) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "invalid_token", "the access token is no longer active");
        }
        return new Me(in.sub(), in.email(), orEmpty(in.roles()), orEmpty(in.permissions()));
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authorization.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    private static List<String> orEmpty(List<String> values) {
        return values == null ? List.of() : values;
    }
}
