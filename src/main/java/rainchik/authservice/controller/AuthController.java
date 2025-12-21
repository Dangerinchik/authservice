package rainchik.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rainchik.authservice.dto.AuthRequest;
import rainchik.authservice.dto.AuthResponse;
import rainchik.authservice.dto.UserRegistration;
import rainchik.authservice.exception.InvalidRefreshTokenException;
import rainchik.authservice.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest authRequest) {
        AuthResponse authResponse = authService.create(authRequest);
        return ResponseEntity.ok(authResponse);

    }
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestParam String token) {
        return ResponseEntity.ok(authService.validateToken(token));
    }
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestParam String token) throws InvalidRefreshTokenException {
        AuthResponse response = authService.refreshToken(token);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/save")
    public ResponseEntity<String> saveCredentials(@RequestBody UserRegistration userRegistration) {
        authService.saveUserCredentials(userRegistration);
        return ResponseEntity.ok("User credentials saved successfully");

    }

    @DeleteMapping("/credentials")
    public ResponseEntity<String> deleteCredentials(@RequestParam String email) {
        return ResponseEntity.noContent().build();
    }
}
