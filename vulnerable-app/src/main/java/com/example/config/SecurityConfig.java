// src/main/java/com/example/vulnerableapp/config/SecurityConfig.java
package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    /**
     * This bean defines the security rules for HTTP requests.
     * It specifies which URL patterns are public and which require authentication.
     * It also disables features like CSRF for stateless APIs and configures headers.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for simple API testing
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/register", "/h2-console/**").permitAll() // Allow public access
                        .anyRequest().authenticated() // Secure all other endpoints
                )
                // H2 console requires frame options to be disabled
                .headers(headers -> headers.frameOptions().disable());

        return http.build();
    }

    /**
     * This bean defines the password hashing algorithm to be used in the application.
     * By defining it as a bean, Spring can inject it wherever it's needed,
     * such as in the AuthController for registering users and verifying passwords.
     * BCrypt is a strong, industry-standard hashing algorithm.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}