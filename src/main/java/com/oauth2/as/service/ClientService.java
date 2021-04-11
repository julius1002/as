package com.oauth2.as.service;

import com.oauth2.as.entities.Client;

public class ClientService {
    public Client getClient() {
            return new Client(1L,
                "default_client",
                "http://localhost:3000",
                "http://localhost:3000/redirect",
                "authorization_code",
                "code",
                "secret_basic",
                "read write",
                "sec123");
    }
}
