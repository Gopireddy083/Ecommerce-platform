package com.ecommerce.user_service.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ecommerce.user_service.dto.AuthResponse;
import com.ecommerce.user_service.dto.LoginRequest;
import com.ecommerce.user_service.dto.RegisterRequest;
import com.ecommerce.user_service.entity.Role;
import com.ecommerce.user_service.entity.User;
import com.ecommerce.user_service.exception.UserAlreadyExistsException;
import com.ecommerce.user_service.repository.UserRepository;

import lombok.RequiredArgsConstructor; 

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
          if (userRepository.existsByEmail(request.getEmail())) {
              throw new UserAlreadyExistsException("Email already registered: " + request.getEmail());
          }

          User user = User.builder()
                  .firstName(request.getFirstName())
                  .lastName(request.getLastName())
                  .email(request.getEmail())
                  .password(passwordEncoder.encode(request.getPassword()))
                  .phone(request.getPhone())
                  .role(Role.ROLE_USER)
                  .enabled(true)
                  .build();

          userRepository.save(user);

          String token = jwtService.generateToken(user);

          return AuthResponse.builder()
                  .token(token)
                  .email(user.getEmail())
                  .firstName(user.getFirstName())
                  .role(user.getRole().name())
                  .message("Registration successful")
                  .build();
    }

      public AuthResponse login(LoginRequest request) {
          authenticationManager.authenticate(
                  new UsernamePasswordAuthenticationToken(
                          request.getEmail(),
                          request.getPassword()
                  )
          );

          User user = userRepository.findByEmail(request.getEmail())
                  .orElseThrow(() -> new RuntimeException("User not found"));

          String token = jwtService.generateToken(user);

          return AuthResponse.builder()
                  .token(token)
                  .email(user.getEmail())
                  .firstName(user.getFirstName())
                  .role(user.getRole().name())
                  .message("Login successful")
                  .build();
      }
}
