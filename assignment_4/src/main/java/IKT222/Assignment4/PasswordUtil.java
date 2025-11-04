package IKT222.Assignment4;

import org.mindrot.jbcrypt.BCrypt;

/** Small wrapper around BCrypt with a sensible cost factor. */
public final class PasswordUtil {

    // Cost 12 is a good default for local coursework; tune as needed
    private static final int BCRYPT_COST = 12;

    private PasswordUtil() {}

    /** Hash a plaintext password with BCrypt. */
    public static String hash(String plaintext) {
        if (plaintext == null) plaintext = "";
        String salt = BCrypt.gensalt(BCRYPT_COST);
        return BCrypt.hashpw(plaintext, salt);
    }

    /** Verify a candidate password against a stored BCrypt hash. */
    public static boolean verify(String candidate, String storedHash) {
        if (candidate == null || storedHash == null || storedHash.isEmpty()) return false;
        try {
            return BCrypt.checkpw(candidate, storedHash);
        } catch (IllegalArgumentException e) {
            // if storedHash is malformed, fail closed
            return false;
        }
    }
}
