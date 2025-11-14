package com.example.auth.exception;

public class InvalidCredentialEx extends RuntimeException{
    public InvalidCredentialEx(String message){
        super(message);
    }
}
