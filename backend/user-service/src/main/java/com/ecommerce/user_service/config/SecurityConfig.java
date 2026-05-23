package com.ecommerce.user_service.config;

  import com.ecommerce.user_service.repository.UserRepository;
  import lombok.RequiredArgsConstructor;
  import org.springframework.context.annotation.*;
  import org.springframework.security.authentication.*;
  import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
  import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
  import org.springframework.security.config.annotation.web.builders.HttpSecurity;
  import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
  import org.springframework.security.config.http.SessionCreationPolicy;
  import org.springframework.security.core.userdetails.*;
  import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
  import org.springframework.security.crypto.password.PasswordEncoder;
  import org.springframework.security.web.SecurityFilterChain;

  @Configuration
  @EnableWebSecurity
  @RequiredArgsConstructor
  public class SecurityConfig {

      private final UserRepository userRepository;

      @Bean
      public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
          http
              .csrf(csrf -> csrf.disable())
              .sessionManagement(session ->
                  session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
              .authorizeHttpRequests(auth -> auth
                  .requestMatchers("/api/auth/**").permitAll()
                  .anyRequest().authenticated()
              );
          return http.build();
      }

      @Bean
      public UserDetailsService userDetailsService() {
          return email -> userRepository.findByEmail(email)
                  .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
      }

      @Bean
      public PasswordEncoder passwordEncoder() {
          return new BCryptPasswordEncoder();
      }

      @Bean
      public AuthenticationProvider authenticationProvider() {
          DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
          provider.setUserDetailsService(userDetailsService());
          provider.setPasswordEncoder(passwordEncoder());
          return provider;
      }

      @Bean
      public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
              throws Exception {
          return config.getAuthenticationManager();
      }
  }
