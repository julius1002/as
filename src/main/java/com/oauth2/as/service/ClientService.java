package com.oauth2.as.service;

import com.oauth2.as.entities.Client;
import com.oauth2.as.entities.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

public class ClientService {

    private Connection databaseConnection;

    public ClientService(Connection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public Optional<Client> findById(Long id) {
        Optional<Client> clientOptional = Optional.empty();
        try {
            PreparedStatement preparedStatement = databaseConnection.prepareStatement("SELECT * FROM client WHERE client.id = ?");
            preparedStatement.setLong(1, id);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                var client = new Client();
                client.setSecret(resultSet.getString("secret"));
                client.setName(resultSet.getString("name"));
                client.setUri(resultSet.getString("uri"));
                client.setRedirectUri(resultSet.getString("redirect_uri"));
                client.setGrantType(resultSet.getString("grant_type"));
                client.setResponseType(resultSet.getString("response_type"));
                client.setTokenEndpointAuthMethod(resultSet.getString("tokenEndpointAuthMethod"));
                client.setScope(resultSet.getString("scope"));
                client.setId(resultSet.getLong("id"));
                clientOptional = Optional.of(client);
            }
        } catch (SQLException throwables) {
            return clientOptional;
        }
        return clientOptional;

    }
}
