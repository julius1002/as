package com.oauth2.as.filter;

import spark.Filter;
import spark.Request;
import spark.Response;

import java.util.Base64;

import static spark.Spark.halt;

public class AuthenticationFilter implements Filter {

    public String[] resolveCredentials(Request request) {

        var authorization = request.headers("Authorization");

        if(authorization == null){
            halt(401);
        }
        String[] splitAuthorization = authorization.split(" ");

        if (!splitAuthorization[0].equals("Basic") && splitAuthorization.length != 2) {
            halt(401);
        }

        var decodedCredentials = new String(Base64.getDecoder().decode(splitAuthorization[1]));

        return decodedCredentials.split(":");
    }

    @Override
    public void handle(Request request, Response response) throws Exception {

    }
}
