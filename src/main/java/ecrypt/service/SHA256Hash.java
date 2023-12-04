package ecrypt.service;

import ecrypt.exception.EncryptionException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SHA256Hash {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public String convert(String plain, String salt) {
        return convert(plain + salt);
    }

    public String convert(String plain) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var hash = digest.digest(plain.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new EncryptionException("Error while decrypt SHA256", e);
        }
    }

    public String getSalt(int n) {
        var bytes = new byte[n];
        SECURE_RANDOM.nextBytes(bytes);
        return new String(bytes);
    }

    public String getSalt() {
        return getSalt(20);
    }
}
