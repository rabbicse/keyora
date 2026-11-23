package com.example.notes;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Calls Keyora's REST API on behalf of this application.
 *
 * <p>Every call carries the client ID and secret as HTTP Basic credentials, which is why
 * this class lives on the server and its calls are never made from a browser.
 */
@Component
public class KeyoraClient {

    private final RestClient http;
    private final ObjectMapper json;

    public KeyoraClient(RestClient.Builder builder, KeyoraProperties keyora, ObjectMapper json) {
        this.http = builder
                .baseUrl(keyora.url())
                .defaultHeaders(headers -> headers.setBasicAuth(keyora.clientId(), keyora.clientSecret()))
                .build();
        this.json = json;
    }

    /**
     * Keyora's answer: the HTTP status and the two halves of its envelope
     * ({@code {"data": ..., "error": ..., "meta": ...}}). Either half may be null.
     */
    public record Response(int status, JsonNode data, JsonNode error) {
    }

    /** The live state of a token as reported by Keyora. Only {@code active} is always present. */
    public record Introspection(boolean active, String sub, String email, List<String> roles,
                                List<String> permissions) {
    }

    /** Keyora answered, but not in the way its API describes. */
    public static class UnexpectedResponseException extends RuntimeException {
        public UnexpectedResponseException(String message) {
            super(message);
        }
    }

    public Response register(Map<String, Object> body) {
        return post("/api/v1/auth/register", body);
    }

    public Response login(Map<String, Object> body) {
        return post("/api/v1/auth/login", body);
    }

    public Response refresh(Map<String, Object> body) {
        return post("/api/v1/auth/refresh", body);
    }

    public Response logout(Map<String, Object> body) {
        return post("/api/v1/auth/logout", body);
    }

    /** Asks Keyora whether an access token is valid right now. */
    public Introspection introspect(String token) {
        Response res = post("/api/v1/auth/introspect", Map.of("token", token));
        if (res.status() != 200 || res.data() == null) {
            throw new UnexpectedResponseException("introspection failed with status " + res.status());
        }
        return json.convertValue(res.data(), Introspection.class);
    }

    /**
     * Sends a JSON body and returns whatever Keyora answered. A 4xx or 5xx status is a
     * normal return value here, not an exception: the caller passes Keyora's error code
     * and status on unchanged. Only a network failure or an unparseable body throws
     * (as a RestClientException).
     */
    private Response post(String path, Object body) {
        return http.post()
                .uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(body)
                // exchange() skips RestClient's default "throw on 4xx/5xx" handling.
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    byte[] raw = response.getBody().readAllBytes();
                    if (raw.length == 0) { // 204 from logout
                        return new Response(status, null, null);
                    }
                    JsonNode envelope = json.readTree(raw);
                    return new Response(status, field(envelope, "data"), field(envelope, "error"));
                });
    }

    private static JsonNode field(JsonNode envelope, String name) {
        JsonNode node = envelope.get(name);
        return node == null || node.isNull() ? null : node;
    }
}
