package com.oauth2.as.service;

import com.oauth2.as.entities.User;

public class UserService {
    public User findUser() {
        return new User(1L, "alice", "secret");
    }
}
