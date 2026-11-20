package com.zeroproof.api;

/** Operational error carrying an HTTP status and machine-readable code. */
public class ApiException extends RuntimeException {
    private final int status;
    private final String code;

    public ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int status() { return status; }

    public String code() { return code; }

    public static ApiException badRequest(String code, String msg) { return new ApiException(400, code, msg); }

    public static ApiException notFound(String code, String msg) { return new ApiException(404, code, msg); }
}
