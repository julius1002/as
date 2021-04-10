package com.oauth2.as.filter;

import com.oauth2.as.service.UserService;
import spark.Request;
import spark.Response;


import static spark.Spark.halt;

public class UserAuthenticationFilter extends AuthenticationFilter {

    private UserService userService;

    public UserAuthenticationFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void handle(Request request, Response response) throws Exception {
        var session = request.session();

        if (session.isNew()) {
            session.invalidate();
            response.redirect("error.html");
            return;
        }

        String[] splitCredentials = resolveCredentials(request);

        if (splitCredentials.length != 2) {
            halt(401);
        }

        var user = userService.findUser();

        if (!user.getUsername().equals(splitCredentials[0]) || !user.getPassword().equals(splitCredentials[1])) {
            halt(401);
            return;
        }

        session.attribute("user", user);
    }
}
