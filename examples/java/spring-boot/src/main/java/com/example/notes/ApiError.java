package com.example.notes;

/** The error body every endpoint uses: {@code {"error": {"code": "...", "message": "..."}}}. */
public record ApiError(Detail error) {

    public record Detail(String code, String message) {
    }

    public static ApiError of(String code, String message) {
        return new ApiError(new Detail(code, message));
    }
}
