package com.oauth2.as.filter;

import com.oauth2.as.service.PRService;
import spark.Request;
import spark.Response;

import static spark.Spark.halt;

public class PRAuthorizationFilter extends BasicAuthorizationFilter {

    private PRService prService;

    public PRAuthorizationFilter(PRService prService) {
        this.prService = prService;
    }

    @Override
    public void handle(Request request, Response response) {

        var splitCredentials = resolveCredentials(request);

        if (splitCredentials.length != 2) {
            halt(401);
        }

        var pr = prService.getPR();

        if (!pr.getId().toString().equals(splitCredentials[0]) || !pr.getSecret().equals(splitCredentials[1])) {
            halt(401);
            return;
        }
    }
}
