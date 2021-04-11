package com.oauth2.as.entities;

public class User {
    private Long id;
    private String username;
    private String secret;

    public User(Long id, String username, String secret) {
        this.id = id;
        this.username = username;
        this.secret = secret;
    }

    public User() {
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}
