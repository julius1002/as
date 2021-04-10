package com.oauth2.as.entities;

public class Client {
    private Long id;
    private String secret;
    private String name;
    private String uri;
    private String redirectUri;
    private String grantType;
    private String responseType;
    private String tokenEndpointAuthMethod;
    private String scope;

    public Client() {
    }

    public Client(Long id, String name, String uri, String redirectUri, String grantType, String responseType, String tokenEndpointAuthMethod, String scope, String secret) {
        this.id = id;
        this.name = name;
        this.uri = uri;
        this.redirectUri = redirectUri;
        this.grantType = grantType;
        this.responseType = responseType;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.scope = scope;
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }
}
