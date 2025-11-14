package com.example.auth.exception;

public class ResourceNotFoundEx extends RuntimeException {
    public ResourceNotFoundEx(String message) {
        super(message);
    }
}
