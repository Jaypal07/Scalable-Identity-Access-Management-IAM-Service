package com.jaypal.authapp.services;

import com.jaypal.authapp.dtos.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
