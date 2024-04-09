package vn.botstore.code.user.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import vn.botstore.code.user.dto.request.LoginRequest;
import vn.botstore.code.user.dto.request.SignupRequest;
import vn.botstore.code.user.dto.request.TokenRefreshRequest;
import vn.botstore.code.user.dto.request.TokenRequest;
import vn.botstore.code.user.dto.response.*;
import vn.botstore.code.user.security.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.botstore.code.user.service.UserService;

import java.util.List;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequiredArgsConstructor
@RequestMapping("/v1/api/user")
public class AuthController {
    private final UserService userService;
    private final JwtUtils jwtUtils;
    private final Environment env;

    /**
     * Home string.
     *
     * @return the string
     */
    @GetMapping("/hello")
    public String home() {
        return "Hello from user running at port: " + env.getProperty("local.server.port");
    }

    /**
     * Refreshtoken response entity.
     *
     * @param tokenRefreshRequest the request
     * @return the response entity
     */
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest tokenRefreshRequest) {
        return userService.refreshtoken(tokenRefreshRequest);
    }

    /**
     * Authenticate user response entity.
     *
     * @param loginRequest the login request
     * @return the response entity
     */
    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(HttpServletResponse response,
                                              @Valid @RequestBody LoginRequest loginRequest) {
        return userService.signIn(response, loginRequest);
    }


    /**
     * Logout user response entity.
     *
     * @param headerAuth the header auth
     * @return the response entity
     */
    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
            return userService.logoutUser(request);
    }

    /**
     * Register user response entity.
     *
     * @param signUpRequest the sign-up request
     * @return the response entity
     */
    @PostMapping("/sign-up")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.signUp(signUpRequest);
    }

    /**
     * Authenticate response entity.
     *
     * @param tokenRequest the token request
     * @return the response entity
     */
    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@Valid @RequestBody TokenRequest tokenRequest){
        if (jwtUtils.validateJwtToken(tokenRequest.getToken())) {
            String userName = jwtUtils.getUserNameFromJwtToken(tokenRequest.getToken());
            Claims claims = jwtUtils.getPayloadFromJwtToken(tokenRequest.getToken());
            List<String> roles = claims.get("role",List.class);
            return ResponseEntity.ok(new AuthenticateResponse(userName,roles));
        }
        return ResponseEntity.ok(new MessageResponse("Invalid token"));
    }
}





















