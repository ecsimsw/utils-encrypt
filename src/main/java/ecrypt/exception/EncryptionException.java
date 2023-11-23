package ecrypt.exception;

public class EncryptionException extends IllegalArgumentException {

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
