package com.oauth2.as.filter;

import com.oauth2.as.service.ClientService;
import spark.Request;
import spark.Response;


import static spark.Spark.halt;

public class ClientAuthorizationFilter extends BasicAuthorizationFilter {

    private ClientService clientService;

    public ClientAuthorizationFilter(ClientService clientService) {
        this.clientService = clientService;
    }

    @Override
    public void handle(Request request, Response response) {

        var splitCredentials = resolveCredentials(request);

        if (splitCredentials.length != 2) {
            halt(401);
        }

        var optionalClient = clientService.findById(Long.parseLong(splitCredentials[0]));

        if (optionalClient.isEmpty()) {
            log("client not found");
            halt(401);
        }
        var client = optionalClient.get();

        request.attribute("client", client);

        if (!client.getSecret().equals(splitCredentials[1])) {
            log("client secret wrong");
            halt(401);
        }
    }

    public static void log(String log) {
        System.out.println(log);
    }
}
