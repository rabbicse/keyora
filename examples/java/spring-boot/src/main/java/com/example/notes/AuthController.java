package com.example.notes;

import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Sign-up, sign-in and the token lifecycle. Each endpoint forwards the request body to
 * Keyora with the application's credentials attached and relays the answer: the same
 * status, and either the envelope's {@code data} object or its {@code error} object.
 */
@RestController
public class AuthController {

    private final KeyoraClient keyora;

    public AuthController(KeyoraClient keyora) {
        this.keyora = keyora;
    }

    @PostMapping("/register")
    ResponseEntity<?> register(@RequestBody Map<String, Object> body) {
        return relay(keyora.register(body));
    }

    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody Map<String, Object> body) {
        return relay(keyora.login(body));
    }

    @PostMapping("/refresh")
    ResponseEntity<?> refresh(@RequestBody Map<String, Object> body) {
        return relay(keyora.refresh(body));
    }

    @PostMapping("/logout")
    ResponseEntity<?> logout(@RequestBody Map<String, Object> body) {
        return relay(keyora.logout(body));
    }

    private static ResponseEntity<?> relay(KeyoraClient.Response res) {
        if (res.status() >= 400) {
            if (res.error() == null) {
                throw new KeyoraClient.UnexpectedResponseException("status " + res.status() + " without an error body");
            }
            // Keyora's error code and status go to the caller unchanged.
            return ResponseEntity.status(res.status()).body(Map.of("error", res.error()));
        }
        JsonNode data = res.data();
        return data == null
                ? ResponseEntity.status(res.status()).build()
                : ResponseEntity.status(res.status()).body(data);
    }
}
