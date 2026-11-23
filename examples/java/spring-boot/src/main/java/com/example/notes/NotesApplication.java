package com.example.notes;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * A notes API protected by Keyora.
 *
 * <p>The application plays two roles:
 * <ul>
 *   <li>Backend for a frontend: /register, /login, /refresh and /logout forward to Keyora
 *       with the application's client secret attached ({@link AuthController}).</li>
 *   <li>Resource server: /me, /notes and /reports verify the access token locally against
 *       Keyora's JWKS and check permissions and roles ({@link SecurityConfig}).</li>
 * </ul>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class NotesApplication {

    public static void main(String[] args) {
        SpringApplication.run(NotesApplication.class, args);
    }
}
