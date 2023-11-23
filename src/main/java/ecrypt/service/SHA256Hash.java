package ecrypt.service;

import ecrypt.exception.EncryptionException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class SHA256Hash {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final MessageDigest MESSAGE_DIGEST;

    static {
        try {
            MESSAGE_DIGEST = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Failed to instance SHA256Hash", e);
        }
    }

    public String convert(String text, String key) {
        try {
            var plain = text + key;
            var hash = MESSAGE_DIGEST.digest(plain.getBytes(StandardCharsets.UTF_8));
            return Arrays.toString(hash);
        } catch (Exception e) {
            throw new EncryptionException("Error while decrypt AES256", e);
        }
    }

    public String getSalt(int n) {
        var bytes = new byte[n];
        SECURE_RANDOM.nextBytes(bytes);
        return Arrays.toString(bytes);
    }

    public String getSalt() {
        return getSalt(20);
    }
}
