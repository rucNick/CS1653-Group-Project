package com.example.spring.service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {
    private final BCryptPasswordEncoder passwordEncoder;

    // Configure work factor in application.properties: security.bcrypt.strength=12
    public PasswordService(@Value("${security.bcrypt.strength:12}") int strength) {
        this.passwordEncoder = new BCryptPasswordEncoder(strength);
    }

    // Hash password
    public String hashPassword(String plainPassword) {
        return passwordEncoder.encode(plainPassword);
    }

    // Verify password
    public boolean verifyPassword(String plainPassword, String hashedPassword) {
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}
