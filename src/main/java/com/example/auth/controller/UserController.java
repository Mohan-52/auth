package com.example.auth.controller;

import com.example.auth.dto.ResponseDto;
import com.example.auth.dto.auth.AuthRequestDto;
import com.example.auth.dto.auth.AuthResponseDto;
import com.example.auth.dto.auth.LoginRequestDto;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.CustomUserDetailsService;
import com.example.auth.security.JwtUtil;
import com.example.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.rmi.server.UID;
import java.util.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class UserController {
    private final UserService userService;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate;

    private final CustomUserDetailsService customUserDetailsService;

    private final UserRepository userRepository;

    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<ResponseDto> registerUser(@RequestBody AuthRequestDto requestDto){
        return new ResponseEntity<>(userService.registerUser(requestDto), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> registerUser(@RequestBody LoginRequestDto requestDto){
        return ResponseEntity.ok(userService.login(requestDto));
    }

    @PostMapping("/google")
    public  ResponseEntity<?> handleGoogleCallBack(@RequestParam String code){
        try {
            // 1 Exchange auth code for token
            String tokenEndpoint="https://oauth2.googleapis.com/token";
            MultiValueMap<String, String> params=new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id",clientId);
            params.add("client_secret", clientSecret);
            params.add("redirect_uri", "https://developers.google.com/oauthplayground");
            params.add("grant_type","authorization_code");

            HttpHeaders headers=new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);


            HttpEntity<MultiValueMap<String, String>> request=new HttpEntity<>(params,headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(tokenEndpoint, request, Map.class);
            String idToken=(String) response.getBody().get("id_token");
            String userInfoUrl="https://oauth2.googleapis.com/tokeninfo?id_token="+idToken;
            ResponseEntity<Map> userInfoResponse= restTemplate.getForEntity(userInfoUrl,Map.class);
            if (userInfoResponse.getStatusCode()==HttpStatus.OK){
                Map<String, Object> userInfo=userInfoResponse.getBody();
                String email=(String) userInfo.get("email");


                if(!userRepository.existsByEmail(email)){
                    User user=User.builder()
                            .email(email)
                            .name(email)
                            .role(Role.USER)
                            .password(UUID.randomUUID().toString()).build();
                    userRepository.save(user);

                    String jwtToken=jwtUtil.generateToken(email);

                    return ResponseEntity.ok(Collections.singletonMap("jwtToken", jwtToken));


                }

                

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();


            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }catch (Exception ex){
            log.error("Error OCuuredd during this process");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

        }
    }
}
