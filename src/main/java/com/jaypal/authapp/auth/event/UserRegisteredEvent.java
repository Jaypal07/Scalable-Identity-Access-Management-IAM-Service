package com.jaypal.authapp.auth.event;

import com.jaypal.authapp.user.model.User;

public record UserRegisteredEvent(User user) {}
