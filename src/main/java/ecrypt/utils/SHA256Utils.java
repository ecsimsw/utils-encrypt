package ecrypt.utils;

import ecrypt.exception.EncryptionException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class SHA256Utils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String encrypt(String text, String key) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var plain = text + key;
            var hash = digest.digest(plain.getBytes(StandardCharsets.UTF_8));
            return Arrays.toString(hash);
        } catch (Exception e) {
            throw new EncryptionException("Error while decrypt AES256", e);
        }
    }

    public static String getSalt(int n) {
        var bytes = new byte[n];
        SECURE_RANDOM.nextBytes(bytes);
        return Arrays.toString(bytes);
    }

    public static String getSalt() {
        return getSalt(20);
    }
}
