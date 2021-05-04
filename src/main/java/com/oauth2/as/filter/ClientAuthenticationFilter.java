package com.oauth2.as.filter;

import com.oauth2.as.service.ClientService;
import spark.Filter;
import spark.Request;
import spark.Response;


import static spark.Spark.halt;

public class ClientAuthenticationFilter extends AuthenticationFilter {

    private ClientService clientService;

    public ClientAuthenticationFilter(ClientService clientService) {
        this.clientService = clientService;
    }

    @Override
    public void handle(Request request, Response response) {

        var splitCredentials = resolveCredentials(request);

        if (splitCredentials.length != 2) {
            halt(401);
        }

        var client = clientService.getClient();

        if (!client.getId().toString().equals(splitCredentials[0]) || !client.getSecret().equals(splitCredentials[1])) {
            halt(401);
        }
    }
}
