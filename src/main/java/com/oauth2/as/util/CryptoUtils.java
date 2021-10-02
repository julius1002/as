package com.oauth2.as.util;

import com.nimbusds.jose.jwk.JWKSet;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;

public class CryptoUtils {


    public CryptoUtils() {

    }

    private Base64.Encoder getEncoder() {
        return Base64.getUrlEncoder();
    }

    public String generateRandomString(Integer size) {
        var bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return getEncoder().withoutPadding().encodeToString(bytes);
    }

    public String sha256(String message) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.getBytes());
        return getEncoder().withoutPadding().encodeToString(digest);
    }
}

