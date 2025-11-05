package rainchik.authservice.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import rainchik.authservice.data.UserDetailsImpl;

import java.util.Map;
//честно говоря я бы лучше использовал @PreAuthorize над методами контроллеров в других сервисах, но пусть будет так
@Component("resourceSecurity")
public class ResourceSecurityUtil {

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    public boolean checkUserId(Authentication authentication, HttpServletRequest request) {
        String path = request.getServletPath();
        Long userId = extractUserIdFromPath(path);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        if (userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_admin"))) {
            return true;
        }

        return userDetails.getId().equals(userId);
    }

    public boolean checkUserEmail(Authentication authentication, HttpServletRequest request) {
        String path = request.getServletPath();
        String email = extractEmailFromPath(path);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        if (userDetails.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_admin"))) {
            return true;
        }

        return userDetails.getEmail().equals(email);
    }

    private Long extractUserIdFromPath(String path) {
        try {
            Map<String, String> variables = pathMatcher.extractUriTemplateVariables("/user/{id}/**", path);
            String idStr = variables.get("id");
            return Long.parseLong(idStr);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid user ID in path: " + path);
        }
    }

    private String extractEmailFromPath(String path) {
        try {
            Map<String, String> variables = pathMatcher.extractUriTemplateVariables("/user/email/{email}", path);
            return variables.get("email");
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid email in path: " + path);
        }
    }

}
