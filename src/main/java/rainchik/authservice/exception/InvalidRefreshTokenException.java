package rainchik.authservice.exception;

public class InvalidRefreshTokenException extends Exception{
    public InvalidRefreshTokenException(String message) {
        super("Invalid refresh token: " + message);
    }
}
