package rainchik.authservice.service;

import rainchik.authservice.dto.AuthRequest;
import rainchik.authservice.dto.AuthResponse;
import rainchik.authservice.dto.UserRegistration;
import rainchik.authservice.exception.InvalidRefreshTokenException;
import rainchik.authservice.exception.UserNotFoundException;

public interface AuthService {

    public AuthResponse create(AuthRequest authRequest);
    public Boolean validateToken(String token);
    public AuthResponse refreshToken(String refreshToken) throws InvalidRefreshTokenException;
    public void saveUserCredentials(UserRegistration userRegistration);
    public void deleteUserCredentials(String email) throws UserNotFoundException;

}
