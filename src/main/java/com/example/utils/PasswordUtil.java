package com.example.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordUtil {
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    public static String encodePassword(String rawPassword) {
        return encoder.encode(rawPassword);
    }
}
