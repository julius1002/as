package com.oauth2.as.service;

import com.oauth2.as.entities.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import static spark.Spark.halt;

public class UserService {


    private Connection databaseConnection;

    public UserService(Connection databaseConnection) {
        this.databaseConnection = databaseConnection;
    }

    public Optional<User> findByUsername(String username) {
        Optional<User> userOptional = Optional.empty();
        try {
            PreparedStatement preparedStatement = databaseConnection.prepareStatement("SELECT * FROM user WHERE user.username = ?");
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                var user = new User();
                user.setUsername(username);
                user.setId(resultSet.getLong("id"));
                user.setSecret(resultSet.getString("secret"));
                userOptional = Optional.of(user);
            }
        } catch (SQLException throwables) {
            return userOptional;
        }
        return userOptional;

    }
}
