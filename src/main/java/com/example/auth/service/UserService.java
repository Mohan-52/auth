package com.example.auth.service;

import com.example.auth.dto.ResponseDto;
import com.example.auth.dto.auth.AuthRequestDto;
import com.example.auth.dto.auth.AuthResponseDto;
import com.example.auth.dto.auth.LoginRequestDto;
import com.example.auth.entity.User;
import com.example.auth.exception.InvalidCredentialEx;
import com.example.auth.exception.ResourceAlreadyExists;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public ResponseDto registerUser(AuthRequestDto requestDto){

        if(userRepository.existsByEmail(requestDto.getEmail())){
            throw new ResourceAlreadyExists("User already with given email");
        }

        User user= User.builder()
                .name(requestDto.getName())
                .email(requestDto.getEmail())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .role(requestDto.getRole())
                .build();

        userRepository.save(user);

        return new ResponseDto("User successfully create");

    }

    public AuthResponseDto login(LoginRequestDto requestDto){
        try{
           authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                   requestDto.getEmail(),requestDto.getPassword()
           ));
        }catch (Exception ex){

            throw new InvalidCredentialEx("Invalid email or password");

        }

        return new AuthResponseDto(jwtUtil.generateToken(requestDto.getEmail()));
    }


}
