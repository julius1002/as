package com.oauth2.as;

import com.oauth2.as.filter.ClientAuthenticationFilter;
import com.oauth2.as.filter.PRAuthenticationFilter;
import com.oauth2.as.filter.UserAuthenticationFilter;
import com.oauth2.as.service.ClientService;
import com.oauth2.as.service.PRService;
import com.oauth2.as.service.UserService;
import com.oauth2.as.util.CryptoUtils;
import org.apache.velocity.app.VelocityEngine;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONObject;
import spark.ModelAndView;
import spark.QueryParamsMap;
import spark.template.velocity.VelocityTemplateEngine;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;
import static spark.Spark.*;

public class App {

    public static String render(VelocityTemplateEngine velocityTemplateEngine, String view, Map<String, Object> model) {
        return velocityTemplateEngine.render(new ModelAndView(model, view));
    }

    public static void main(String[] args) throws SQLException {

        staticFileLocation("/public");

        Properties properties = new Properties();

        properties.setProperty("file.resource.loader.path", "src/main/resources/public");

        VelocityTemplateEngine templateEngine = new VelocityTemplateEngine(new VelocityEngine(properties));

        var jdbcConnectionPool = JdbcConnectionPool.create("jdbc:h2:~/test", "sa", "sa");

        var connection = jdbcConnectionPool.getConnection();

        connection.createStatement().execute("DROP TABLE code");

        connection.createStatement().execute("DROP TABLE token");

        var codeTableQuery = "CREATE TABLE IF NOT EXISTS code (id int IDENTITY(1,1) PRIMARY KEY, content VARCHAR(255), expiry TIMESTAMP, scope VARCHAR(255))";

        var tokenTableQuery = "CREATE TABLE IF NOT EXISTS token (id int IDENTITY(1,1) PRIMARY KEY, content VARCHAR (255), expiry TIMESTAMP, scope VARCHAR(255))";

        connection.createStatement().execute(codeTableQuery);

        connection.createStatement().execute(tokenTableQuery);

        var cryptoUtils = new CryptoUtils();

        var userService = new UserService();

        var userAuthenticationFilter = new UserAuthenticationFilter(userService);

        var clientService = new ClientService();

        var clientAuthenticationFilter = new ClientAuthenticationFilter(clientService);

        var prService = new PRService();

        var prAuthenticationFilter = new PRAuthenticationFilter(prService);
                /*
        /authorize endpoint
         */

        get("/authorize", (request, response) -> {

            var client = clientService.getClient();

            request.session();

            try {
                var queryMap = request.queryMap();

                if (!queryMap.hasKeys()) {
                    response.redirect("authorize.html");
                    return null;
                }

                if (!queryMap.hasKey("state")) {
                    var model = new HashMap<String, Object>();
                    model.put("error", "state");
                    return render(templateEngine, "error.html", model);
                }

                var actualClientId = Long.parseLong(request.queryParams("client_id"));

                var realClientId = client.getId();

                if (!realClientId.equals(actualClientId)) {
                    var model = new HashMap<String, Object>();
                    model.put("error", "client_id");
                    return render(templateEngine, "error.html", model);
                }

                var actualRedirectUri = request.queryParams("redirect_uri");

                var realRedirectUri = client.getRedirectUri();

                if (!realRedirectUri.equals(actualRedirectUri)) {
                    var model = new HashMap<String, Object>();
                    model.put("error", "redirect_uri");
                    return render(templateEngine, "error.html", model);
                }

                var actualScope = request.queryParams("scope").split(" ");

                var realScope = client.getScope().split(" ");

                if (!Arrays.asList(realScope).containsAll(Arrays.asList(actualScope))) {
                    var model = new HashMap<String, Object>();
                    model.put("error", "scope");
                    return render(templateEngine, "error.html", model);
                }

            } catch (NumberFormatException e) {
                var model = new HashMap<String, Object>();
                model.put("error", "format");
                return render(templateEngine, "error.html", model);
            }

            request.session().attribute("query_map", request.queryMap());

            var model = new HashMap<String, Object>();

            model.put("scope", request.queryMap().value("scope").split(" "));
            model.put("client", client.getName());
            return render(templateEngine, "authorize.html", model);
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

            var preparedInsertStatement = connection.prepareStatement("INSERT INTO code (content, expiry, scope) VALUES (?, ?, ?)");

            preparedInsertStatement.setString(1, hashedCode);

            preparedInsertStatement.setTimestamp(2, Timestamp.from(expiry));

            preparedInsertStatement.setString(3, queryMap.value("scope"));

            preparedInsertStatement.execute();

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

            var preparedStatement = connection.prepareStatement("SELECT * FROM code WHERE content = ?");

            preparedStatement.setString(1, hashedCode);

            var result = preparedStatement.executeQuery();

            var scope = "";

            if (result.next()) {

                var expiry = result.getTimestamp("expiry").toInstant();

                scope = result.getString("scope");

                var preparedDeleteStatement = connection.prepareStatement("DELETE FROM code WHERE content = ?");

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

            var prepareInsertStatement = connection.prepareStatement("INSERT INTO token (content, expiry, scope) VALUES (? , ?, ?)");

            prepareInsertStatement.setString(1, hashedToken);

            prepareInsertStatement.setTimestamp(2, Timestamp.from(expiry));

            prepareInsertStatement.setString(3, scope);

            prepareInsertStatement.execute();

            var tokenResponse = new JSONObject();

            tokenResponse.put("token", accessToken);

            tokenResponse.put("expiry", expiry);

            return tokenResponse;
        });

        before("/introspect", prAuthenticationFilter);
        post("/introspect", (request, response) -> {
            var requestBody = new JSONObject(request.body());

            if (!requestBody.has("token")) {
                response.status(401);
                return null;
            }

            var responseObject = new JSONObject();

            responseObject.put("active", false);

            var actualToken = (String) requestBody.get("token");

            var hashedToken = cryptoUtils.sha256(actualToken);

            var preparedStatement = connection.prepareStatement("SELECT * FROM token WHERE content = ?");

            preparedStatement.setString(1, hashedToken);

            var result = preparedStatement.executeQuery();

            if (result.next()) {

                var expiry = result.getTimestamp("expiry").toInstant();
                var scope = result.getString("scope");

                if (now().isAfter(expiry)) {
                    var preparedDeleteStatement = connection.prepareStatement("DELETE FROM token WHERE content = ?");
                    preparedDeleteStatement.setString(1, hashedToken);
                    preparedDeleteStatement.execute();
                } else {
                    responseObject.put("expiry", expiry);
                    responseObject.put("active", true);
                    responseObject.put("scope", scope);
                }
            }

            response.status(200);

            return responseObject;

        });
    }
}
