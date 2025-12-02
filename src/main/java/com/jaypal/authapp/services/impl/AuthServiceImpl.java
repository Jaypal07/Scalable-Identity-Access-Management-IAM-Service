package com.jaypal.authapp.services.impl;

import com.jaypal.authapp.dtos.UserDto;
import com.jaypal.authapp.services.AuthService;
import com.jaypal.authapp.services.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;

    @Override
    public UserDto registerUser(UserDto userDto) {
        //logic
        //verify email
        //default role
        return userService.createUser(userDto);
    }
}
