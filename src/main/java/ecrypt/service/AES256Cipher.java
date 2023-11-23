package ecrypt.service;

import ecrypt.exception.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES256Cipher {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_SPEC_ALGORITHM = "AES";

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public AES256Cipher(String key, String iv) {
        try {
            var keySpec = new SecretKeySpec(key.getBytes(), SECRET_KEY_SPEC_ALGORITHM);
            var ivParamSpec = new IvParameterSpec(iv.getBytes());

            this.encryptCipher = Cipher.getInstance(ALGORITHM);
            this.encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

            this.decryptCipher = Cipher.getInstance(ALGORITHM);
            this.decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionException("Failed to initiate AES256 cipher", e);
        }
    }

    public String encrypt(String plain) {
        return new String(encrypt(plain.getBytes()));
    }

    public byte[] encrypt(byte[] plain) {
        try {
            return encryptCipher.doFinal(plain);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new EncryptionException("Error while decrypt AES256", e);
        }
    }

    public String decrypt(String plain) {
        return new String(decrypt(plain.getBytes()));
    }

    public byte[] decrypt(byte[] encrypted) {
        try {
            return decryptCipher.doFinal(encrypted);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new EncryptionException("Error while decrypt AES256", e);
        }
    }
}
