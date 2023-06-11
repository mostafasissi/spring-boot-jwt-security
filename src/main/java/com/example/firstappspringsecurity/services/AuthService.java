package com.example.firstappspringsecurity.services;

import com.example.firstappspringsecurity.DTOs.AuthenticationRequest;
import com.example.firstappspringsecurity.DTOs.AuthenticationResponse;
import com.example.firstappspringsecurity.DTOs.RegisterRequest;
import com.example.firstappspringsecurity.entities.UserInfo;
import com.example.firstappspringsecurity.repositories.UserRepository;
import com.example.firstappspringsecurity.security.JwtService;
import com.example.firstappspringsecurity.security.UserInfoDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository ;

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager ;

    public AuthenticationResponse register(RegisterRequest request) {
        UserInfo user  = UserInfo
                .builder()
                .firstname(request.getFirstName())
                .lastname(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles("USER")
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(new UserInfoDetails(user));
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(new UserInfoDetails(user));
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }
}
