package com.oauth2.as;

import com.oauth2.as.filter.ClientAuthenticationFilter;
import com.oauth2.as.filter.UserAuthenticationFilter;
import com.oauth2.as.service.ClientService;
import com.oauth2.as.service.UserService;
import com.oauth2.as.util.CryptoUtils;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;
import spark.QueryParamsMap;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Time;
import java.sql.Timestamp;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;
import static spark.Spark.*;

public class App {

    public static void main(String[] args) throws SQLException {

        staticFileLocation("/public");

        var jdbcConnectionPool = JdbcConnectionPool.create("jdbc:h2:~/test", "sa", "sa");

        var connection = jdbcConnectionPool.getConnection();

        var codeTableQuery = "CREATE TABLE IF NOT EXISTS CODE (id int, content varchar(255), expiry TIMESTAMP)";

        var tokenTableQuery = "CREATE TABLE IF NOT EXISTS TOKEN (id int, content varchar(255), expiry TIMESTAMP)";

        connection.createStatement().execute(codeTableQuery);

        connection.createStatement().execute(tokenTableQuery);

        var cryptoUtils = new CryptoUtils();

        var userService = new UserService();

        var userAuthenticationFilter = new UserAuthenticationFilter(userService);

        var clientService = new ClientService();

        var clientAuthenticationFilter = new ClientAuthenticationFilter(clientService);


                /*
        /authorize endpoint
         */

        get("/authorize", (request, response) -> {

            var client = clientService.getClient();

            request.session();

            try {
                var queryMap = request.queryMap();

                if (!queryMap.hasKeys()) {
                    response.redirect("approve.html");
                    return null;
                }

                if (!queryMap.hasKey("state")) {
                    response.redirect("error.html?invalid=state");
                }

                var actualClientId = Long.parseLong(request.queryParams("client_id"));

                var realClientId = client.getId();

                if (!realClientId.equals(actualClientId)) {
                    response.redirect("error.html?invalid=client_id");
                }

                var actualRedirectUri = request.queryParams("redirect_uri");

                var realRedirectUri = client.getRedirectUri();

                if (!realRedirectUri.equals(actualRedirectUri)) {
                    response.redirect("error.html?invalid=redirect_uri");
                }

                var actualScope = request.queryParams("scope");

                var realScope = client.getScope();

                if (!realScope.equals(actualScope)) {
                    response.redirect("error.html?invalid=scope");
                }

            } catch (NumberFormatException e) {
                response.redirect("error.html?invalid=format");
            }

            request.session().attribute("query_map", request.queryMap());

            response.redirect("approve.html?" + request.queryString());

            return null;
        });

        /*
        /approve endpoint
         */

        before("/approve", userAuthenticationFilter);

        post("/approve", (request, response) -> {

            var session = request.session();

            var queryMap = (QueryParamsMap) session.attribute("query_map");

            var code = cryptoUtils.generateRandomString(15);

            var hashedCode = cryptoUtils.sha256(code);

            var expiry = now().plus(10, SECONDS);

            var preparedStatement = connection.prepareStatement("INSERT INTO CODE (content, expiry) VALUES (? , ?)");

            preparedStatement.setString(1, hashedCode);

            preparedStatement.setTimestamp(2, Timestamp.from(expiry));

            preparedStatement.execute();

            var state = queryMap.value("state");

            var redirectUri = queryMap.value("redirect_uri") + "?code=" + code + "&state=" + state;

            var redirectUriResponse = new JSONObject();

            redirectUriResponse.put("redirect_uri", redirectUri);

            response.status(200);

            return redirectUriResponse.toString();
        });

        /*
        /token endpoint
         */

        before("/token", clientAuthenticationFilter);
        post("/token", (request, response) -> {

            var requestBody = new JSONObject(request.body());

            var code = (String) requestBody.get("code");

            var hashedCode = cryptoUtils.sha256(code);

            var preparedStatement = connection.prepareStatement("SELECT * FROM CODE WHERE content = ?");

            preparedStatement.setString(1, hashedCode);

            var result = preparedStatement.executeQuery();

            if (result.next()) {

                var expiry = result.getTimestamp("expiry").toInstant();

                var preparedDeleteStatement = connection.prepareStatement("DELETE FROM CODE WHERE content = ?");

                preparedDeleteStatement.setString(1, hashedCode);

                preparedDeleteStatement.execute();

                if (now().isAfter(expiry)) {
                    halt(401);
                }
            } else {
                halt(401);
            }

            var accessToken = cryptoUtils.generateRandomString(50);

            var expiry = now().plus(30, SECONDS);

            var hashedToken = cryptoUtils.sha256(accessToken);

            var prepareInsertStatement = connection.prepareStatement("INSERT INTO TOKEN (content, expiry) VALUES (? , ?)");

            prepareInsertStatement.setString(1, hashedToken);

            prepareInsertStatement.setTimestamp(2, Timestamp.from(expiry));

            prepareInsertStatement.execute();

            var tokenResponse = new JSONObject();

            tokenResponse.put("token", accessToken);

            return tokenResponse;
        });


        post("/introspection", (request, response) -> {
            var requestBody = new JSONObject(request.body());

            if (!requestBody.has("token")) {
                response.status(401);
                return null;
            }

            var responseObject = new JSONObject();

            responseObject.put("active", false);

            var actualToken = (String) requestBody.get("token");

            var hashedToken = cryptoUtils.sha256(actualToken);

            var preparedStatement = connection.prepareStatement("SELECT * FROM TOKEN WHERE content = ?");

            preparedStatement.setString(1, hashedToken);

            var result = preparedStatement.executeQuery();

            if (result.next()) {

                var expiry = result.getTimestamp("expiry").toInstant();

                if (now().isAfter(expiry)) {
                    connection.createStatement().execute("DELETE FROM TOKEN WHERE content = " + "\'" + hashedToken + "\'");
                } else {
                    responseObject.put("expiry", expiry);
                    responseObject.put("active", true);
                }
            }

            response.status(200);

            return responseObject;

        });
    }
}
