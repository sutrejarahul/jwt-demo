package com.example.service;

import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.utils.PasswordUtil;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User save(User user) {
        user.setPassword(PasswordUtil.encodePassword(user.getPassword()));
        return userRepository.save(user);
    }
}
