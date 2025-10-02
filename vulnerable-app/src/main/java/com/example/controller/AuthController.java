package com.example.controller;

import com.example.model.User;
import com.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
public class AuthController {

    @Autowired
    private UserRepository userRepository;

//    @Autowired
//    private JdbcTemplate jdbcTemplate; // For creating the vulnerability


    @Autowired
    private PasswordEncoder passwordEncoder;


    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        // SECURE: Hash the password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully!");
    }

    // SECURE LOGIN ENDPOINT
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String rawPassword = credentials.get("password");

        // Use Spring Data JPA to find the user safely
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            // Use the password encoder to securely compare the raw password with the stored hash
            if (passwordEncoder.matches(rawPassword, user.getPassword())) {
                // This is where you would generate a secure token (e.g., JWT)
                // For now, we fix the immediate flaw.
                return ResponseEntity.ok("Login Successful! Welcome, " + user.getUsername());
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
    }
}







//    @PostMapping("/register")
//    public ResponseEntity<String> registerUser(@RequestBody User user) {
//        // NOTE: Storing passwords in plain text is a huge vulnerability itself.
//        userRepository.save(user);
//        return ResponseEntity.ok("User registered successfully!");
//    }
//
//
//    // VULNERABLE LOGIN ENDPOINT
//    @PostMapping("/login")
//    public ResponseEntity<String> login(@RequestBody Map<String, String> credentials) {
//        String username = credentials.get("username");
//        String password = credentials.get("password");
//
//        // THIS IS THE SQL INJECTION VULNERABILITY
//        String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
//
//        try {
//            List<Map<String, Object>> users = jdbcTemplate.queryForList(sql);
//            if (!users.isEmpty()) {
//                // WEAK SESSION HANDLING: Returning a predictable "token"
//                return ResponseEntity.ok("Login Successful! Welcome, " + users.get(0).get("USERNAME"));
//            } else {
//                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
//            }
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred: " + e.getMessage());
//        }
//    }
//}
