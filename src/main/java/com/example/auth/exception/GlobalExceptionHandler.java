package com.example.auth.exception;

import com.example.auth.dto.ErrorResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private ResponseEntity<ErrorResponseDto> buildError(Exception ex, HttpStatus status, String path){
        ErrorResponseDto error= ErrorResponseDto.builder()
                .timeStamp(LocalDateTime.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(ex.getMessage())
                .path(path).build();
        return new ResponseEntity<>(error,status);
    }


    @ExceptionHandler(ResourceAlreadyExists.class)
    public ResponseEntity<ErrorResponseDto> handleResourceAlreadyExistsEx(Exception ex, HttpServletRequest request){
        return buildError(ex,HttpStatus.CONFLICT, request.getRequestURI());
    }

    @ExceptionHandler(ResourceNotFoundEx.class)
    public ResponseEntity<ErrorResponseDto> handleResourceNotFoundExistsEx(Exception ex, HttpServletRequest request){
        return buildError(ex,HttpStatus.NOT_FOUND, request.getRequestURI());
    }

    @ExceptionHandler(InvalidCredentialEx.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidCredentialsEx(Exception ex, HttpServletRequest request){
        return buildError(ex,HttpStatus.UNAUTHORIZED, request.getRequestURI());
    }
}
