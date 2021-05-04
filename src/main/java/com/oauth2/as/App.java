package com.oauth2.as;

import com.oauth2.as.entities.User;
import com.oauth2.as.filter.ClientAuthenticationFilter;
import com.oauth2.as.filter.CorsFilter;
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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.*;

import static java.time.Instant.now;
import static java.time.temporal.ChronoUnit.SECONDS;
import static spark.Spark.*;

public class App {

    public static void main(String[] args) throws SQLException, IOException {

        staticFileLocation("/public");

        var templateEngine = initTemplateEngine("src/main/resources/public");

        var jdbcConnectionPool = JdbcConnectionPool.create("jdbc:h2:~/test", "sa", "sa");

        var connection = jdbcConnectionPool.getConnection();

        initDatabase(connection, "src/main/resources/init.sql");

        var cryptoUtils = new CryptoUtils();

        var corsFilter = new CorsFilter(Set.of("*"));

        var userService = new UserService(connection);

        var userAuthenticationFilter = new UserAuthenticationFilter(userService);

        var clientService = new ClientService();

        var clientAuthenticationFilter = new ClientAuthenticationFilter(clientService);

        var prService = new PRService();

        var prAuthenticationFilter = new PRAuthenticationFilter(prService);

        before(corsFilter);

                /*
        /authorize endpoint
         */
        get("/authorize", (request, response) -> {

            var client = clientService.getClient();

            log(client.getName() + " hit /authorize");

            request.session();

            try {
                var queryMap = request.queryMap();

                if (!queryMap.hasKeys()) {
                    response.redirect("authorize.html");
                    return null;
                }

                if (!queryMap.hasKey("state")) {
                    log("state not present");
                    var model = new HashMap<String, Object>();
                    model.put("error", "state");
                    return render(templateEngine, "error.html", model);
                }

                if (!(queryMap.hasKey("code_challenge") && queryMap.hasKey("code_challenge_method"))) {
                    var model = new HashMap<String, Object>();
                    if (!Set.of("S256", "Plain").contains(queryMap.value("code_challenge_method"))) {
                        model.put("error", "code_challenge_method");
                        log("unsupported code_challenge_method");
                    } else {
                        log("code_challenge not present");
                        model.put("error", "code_challenge");
                    }
                    return render(templateEngine, "error.html", model);
                }

                var actualClientId = Long.parseLong(request.queryParams("client_id"));

                var realClientId = client.getId();

                if (!realClientId.equals(actualClientId)) {
                    log("invalid clientId " + actualClientId + " != " + realClientId);
                    var model = new HashMap<String, Object>();
                    model.put("error", "client_id");
                    return render(templateEngine, "error.html", model);
                }

                var actualRedirectUri = request.queryParams("redirect_uri");

                var realRedirectUri = client.getRedirectUri();

                if (!realRedirectUri.equals(actualRedirectUri)) {
                    log("invalid redirect_uri " + actualRedirectUri + " != " + realRedirectUri);
                    var model = new HashMap<String, Object>();
                    model.put("error", "redirect_uri");
                    return render(templateEngine, "error.html", model);
                }

                var actualScope = request.queryParams("scope").split(" ");

                var realScope = client.getScope().split(" ");

                if (!Arrays.asList(realScope).containsAll(Arrays.asList(actualScope))) {
                    log("invalid scope " + String.join(" ", actualScope) + " != " + String.join(" ", realScope));
                    var model = new HashMap<String, Object>();
                    model.put("error", "scope");
                    return render(templateEngine, "error.html", model);
                }

            } catch (NumberFormatException e) {
                log("invalid format");
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

            log("/approve endpoint hit");

            var session = request.session();

            var queryMap = (QueryParamsMap) session.attribute("query_map");


            var code = cryptoUtils.generateRandomString(15);

            log("code issued: " + code);

            var hashedCode = cryptoUtils.sha256(code);

            var expiry = now().plus(10, SECONDS);

            var user = (User) session.attribute("user");

            var codeChallenge = queryMap.value("code_challenge");

            var codeChallengeMethod = queryMap.value("code_challenge_method");

            var preparedInsertStatement = connection.prepareStatement("INSERT INTO code (content, expiry, scope, user_id, code_challenge_method, code_challenge)" +
                    " VALUES (?, ?, ?, ?, ?, ?)");

            preparedInsertStatement.setString(1, hashedCode);
            preparedInsertStatement.setTimestamp(2, Timestamp.from(expiry));
            preparedInsertStatement.setString(3, queryMap.value("scope"));
            preparedInsertStatement.setLong(4, user.getId());
            preparedInsertStatement.setString(5, codeChallengeMethod);
            preparedInsertStatement.setString(6, codeChallenge);
            preparedInsertStatement.execute();

            var state = queryMap.value("state");

            log("state present: " + state);

            var redirectUri = queryMap.value("redirect_uri") + "?code=" + code + "&state=" + state;

            var redirectUriResponse = new JSONObject();

            redirectUriResponse.put("redirect_uri", redirectUri);

            response.status(200);

            return redirectUriResponse.toString();
        });

        /*
        /token endpoint
         */

        // before("/token", clientAuthenticationFilter);
        post("/token", (request, response) -> {

            log("/token endpoint hit");

            var requestBody = new JSONObject(request.body());

            if (!requestBody.has("code")) {
                log("code not present");
                halt(401);
            }

            if (!requestBody.has("code_verifier")) {
                log("code_verifier not present");
                halt(401);
            }

            var code = (String) requestBody.get("code");

            var hashedCode = cryptoUtils.sha256(code);

            var preparedStatement = connection.prepareStatement("SELECT * FROM code WHERE content = ?");
            preparedStatement.setString(1, hashedCode);
            var result = preparedStatement.executeQuery();

            var scope = "";

            var userId = -1L;

            if (result.next()) {

                log("code found");

                var expiry = result.getTimestamp("expiry").toInstant();

                var codeChallengeMethod = result.getString("code_challenge_method");

                var realCodeChallenge = result.getString("code_challenge");

                var actualCodeVerifier = (String) requestBody.get("code_verifier");

                var actualCodeChallenge = codeChallengeMethod.equals("S256") ? cryptoUtils.sha256(actualCodeVerifier) : actualCodeVerifier;

                if (!actualCodeChallenge.equals(realCodeChallenge)) {
                    log("invalid code_verifier: " + realCodeChallenge + " != " + actualCodeChallenge);
                    halt(401);
                }

                log("valid code_verifier");

                scope = result.getString("scope");

                userId = result.getLong("user_id");

                var preparedDeleteStatement = connection.prepareStatement("DELETE FROM code WHERE content = ?");

                preparedDeleteStatement.setString(1, hashedCode);

                preparedDeleteStatement.execute();

                if (now().isAfter(expiry)) {
                    halt(401);
                }
            } else {
                log("code not found");
                halt(401);
            }

            var accessToken = cryptoUtils.generateRandomString(50);

            log("accessToken issued: " + accessToken);

            var expiry = now().plus(30, SECONDS);

            var hashedToken = cryptoUtils.sha256(accessToken);

            var prepareInsertStatement = connection.prepareStatement("INSERT INTO token (content, expiry, scope, user_id) VALUES (?, ?, ?, ?)");

            prepareInsertStatement.setString(1, hashedToken);

            prepareInsertStatement.setTimestamp(2, Timestamp.from(expiry));

            prepareInsertStatement.setString(3, scope);

            prepareInsertStatement.setLong(4, userId);

            prepareInsertStatement.execute();

            var tokenResponse = new JSONObject();

            tokenResponse.put("token", accessToken);

            tokenResponse.put("expiry", expiry);

            return tokenResponse;
        });

        //before("/introspect", prAuthenticationFilter);
        post("/introspect", (request, response) -> {

            log("/introspect endpoint hit");

            var requestBody = new JSONObject(request.body());

            if (!requestBody.has("token")) {
                log("body contains no token");
                response.status(401);
                return null;
            }

            var introspectionResponse = new JSONObject();

            introspectionResponse.put("active", false);

            var actualToken = (String) requestBody.get("token");
            log("token present: " + actualToken);
            var hashedToken = cryptoUtils.sha256(actualToken);

            var preparedStatement = connection.prepareStatement("SELECT * FROM token WHERE content = ?");
            preparedStatement.setString(1, hashedToken);
            var result = preparedStatement.executeQuery();

            if (result.next()) {

                var expiry = result.getTimestamp("expiry").toInstant();

                var scope = result.getString("scope");

                var sub = result.getLong("user_id");

                if (now().isAfter(expiry)) {
                    var preparedDeleteStatement = connection.prepareStatement("DELETE FROM token WHERE content = ?");
                    preparedDeleteStatement.setString(1, hashedToken);
                    preparedDeleteStatement.execute();
                    log("token expired");
                } else {
                    introspectionResponse.put("expiry", expiry);
                    introspectionResponse.put("active", true);
                    introspectionResponse.put("sub", sub);
                    introspectionResponse.put("scope", scope);
                    log("token valid");
                }
            } else {
                log("token not present in db");
            }
            response.status(200);
            return introspectionResponse;
        });
    }

    private static VelocityTemplateEngine initTemplateEngine(String path) {
        Properties properties = new Properties();

        properties.setProperty("file.resource.loader.path", path);

        VelocityTemplateEngine templateEngine = new VelocityTemplateEngine(new VelocityEngine(properties));
        return templateEngine;
    }

    public static String render(VelocityTemplateEngine velocityTemplateEngine, String view, Map<String, Object> model) {
        return velocityTemplateEngine.render(new ModelAndView(model, view));
    }

    private static void initDatabase(java.sql.Connection connection, String fileName) throws IOException, SQLException {
        var reader = new BufferedReader(new FileReader(fileName));

        var stringBuilder = new StringBuilder();

        while (reader.ready()) {
            stringBuilder.append(reader.readLine());
        }
        connection.createStatement().execute(stringBuilder.toString());
    }

    private static void log(String log) {
        System.out.println(log);
    }
}
