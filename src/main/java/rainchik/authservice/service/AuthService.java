package rainchik.authservice.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import rainchik.authservice.data.UserDetailsImpl;
import rainchik.authservice.dto.AuthRequest;
import rainchik.authservice.dto.AuthResponse;
import rainchik.authservice.dto.UserRegistration;
import rainchik.authservice.exception.InvalidRefreshTokenException;
import rainchik.authservice.repository.UserRepository;
import rainchik.authservice.util.JWTUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public AuthService(AuthenticationManager authenticationManager,
                       JWTUtil jwtUtil,
                       UserDetailsServiceImpl userDetailsService,
                       PasswordEncoder passwordEncoder, UserRepository userRepository){
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;

    }

    public AuthResponse create(AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String accessToken = jwtUtil.generateAccessToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        return new AuthResponse(accessToken, refreshToken, userDetails.getUsername(), userDetails.getAuthorities());
    }

    public Boolean validateToken(String token) {
        return jwtUtil.validateToken(token);
    }

    public AuthResponse refreshToken(String refreshToken) throws InvalidRefreshTokenException {
        if(jwtUtil.validateToken(refreshToken)) {
            String username = jwtUtil.extractUsername(refreshToken);
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);

            String newAccessToken = jwtUtil.generateAccessToken(userDetails);
            String newRefreshToken = jwtUtil.generateRefreshToken(userDetails);

            return new AuthResponse(newAccessToken, newRefreshToken, userDetails.getUsername(), userDetails.getAuthorities());

        }
        throw new InvalidRefreshTokenException(refreshToken);
    }

    public void saveUserCredentials(UserRegistration userRegistration){
        if (userRepository.findByUsername(userRegistration.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        if (userRepository.findByEmail(userRegistration.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        }
        String encodedPassword = passwordEncoder.encode(userRegistration.getPassword());
        UserDetailsImpl user = new UserDetailsImpl();
        user.setUsername(userRegistration.getUsername());
        user.setPassword(encodedPassword);
        user.setEmail(userRegistration.getEmail());
        user.setRoles(List.of(userRegistration.getRole()));
        userRepository.save(user);

    }

}

