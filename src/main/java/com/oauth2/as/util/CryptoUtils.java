package com.oauth2.as.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {

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
        return getEncoder().encodeToString(digest);
    }

}

