package com.example.auth.dto.auth;

import com.example.auth.entity.Role;
import lombok.Data;

@Data
public class AuthRequestDto {
    private String name;
    private String email;
    private String password;
    private Role role;
}
