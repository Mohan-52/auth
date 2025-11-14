package com.example.auth.dto;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class ErrorResponseDto {
    private LocalDateTime timeStamp;
    private int status;
    private String error;
    private String message;
    private String path;
}
