package com.example.notes;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * The application's own data. Access is decided from the authorities that
 * {@link SecurityConfig} derives from the token: a permission keeps its name
 * ({@code notes:read}) and a role gets Spring's {@code ROLE_} prefix ({@code ROLE_editor}).
 */
@RestController
public class NotesController {

    public record Note(String text, String author) {
    }

    public record NewNote(String text) {
    }

    // In memory: this example is about authentication, not storage.
    private final List<Note> notes = new CopyOnWriteArrayList<>(List.of(new Note("Welcome to Keyora", "system")));

    @GetMapping("/public")
    Map<String, String> anyone() {
        return Map.of("message", "anyone can read this");
    }

    /** Permission-based authorization. */
    @GetMapping("/notes")
    @PreAuthorize("hasAuthority('notes:read')")
    Map<String, List<Note>> list() {
        return Map.of("notes", notes);
    }

    @PostMapping("/notes")
    @PreAuthorize("hasAuthority('notes:write')")
    @ResponseStatus(HttpStatus.CREATED)
    Note create(@RequestBody NewNote in, @AuthenticationPrincipal Jwt jwt) {
        if (!StringUtils.hasText(in.text())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "validation_failed", "text is required");
        }
        Note note = new Note(in.text(), jwt.getClaimAsString("email"));
        notes.add(note);
        return note;
    }

    /** Role-based authorization. */
    @GetMapping("/reports")
    @PreAuthorize("hasRole('editor')")
    Map<String, Integer> reports() {
        return Map.of("total_notes", notes.size());
    }
}
