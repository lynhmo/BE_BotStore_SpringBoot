package vn.botstore.code.user.service;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import vn.botstore.code.user.dto.request.LoginRequest;
import vn.botstore.code.user.dto.request.SignupRequest;
import vn.botstore.code.user.dto.request.TokenRefreshRequest;
import vn.botstore.code.user.dto.request.UpdateUser;
import vn.botstore.code.user.dto.response.JwtResponse;
import vn.botstore.code.user.dto.response.MessageResponse;
import vn.botstore.code.user.dto.response.TokenRefreshResponse;
import vn.botstore.code.user.entity.ERole;
import vn.botstore.code.user.entity.RefreshToken;
import vn.botstore.code.user.entity.Role;
import vn.botstore.code.user.entity.User;
import vn.botstore.code.user.exception.TokenRefreshException;
import vn.botstore.code.user.repo.RoleRepository;
import vn.botstore.code.user.repo.UserRepository;
import vn.botstore.code.user.security.JwtUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public ResponseEntity<?> signIn(HttpServletResponse response, LoginRequest loginRequest) {
       try {
           Authentication authentication = authenticationManager.authenticate(
                   new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

           SecurityContextHolder.getContext().setAuthentication(authentication);
           String jwt = jwtUtils.generateJwtToken(authentication);

           UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
           List<String> roles = userDetails.getAuthorities().stream()
                   .map(GrantedAuthority::getAuthority)
                   .collect(Collectors.toList());

           RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

           // create a cookie
           Cookie cookie = new Cookie("AccessToken", jwt);
           cookie.setMaxAge(jwtUtils.jwtExpirationMs);
           cookie.setHttpOnly(true);
           cookie.setSecure(false);
           cookie.setPath("/");
           //add cookie to response
           response.addCookie(cookie);


           return ResponseEntity.ok(new JwtResponse(
                   jwt,
                   refreshToken.getToken(),
                   userDetails.getId(),
                   userDetails.getUsername(),
                   userDetails.getEmail(),
                   roles));
       }catch (Exception ex){
           return ResponseEntity.internalServerError()
                   .body(new MessageResponse("Error: "+ex.getMessage()));
       }
    }

    public ResponseEntity<?> signUp(SignupRequest signUpRequest) {
        try{
            //Check name
            if (userRepository.existsByUsername(signUpRequest.getUsername())) {
                return ResponseEntity.badRequest()
                        .body(new MessageResponse("Error: Username is already taken!"));
            }
            //check mail
            if (userRepository.existsByEmail(signUpRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(new MessageResponse("Error: Email is already in use!"));
            }

            // Create new user's account
            User user = new User(signUpRequest.getUsername(),
                    signUpRequest.getEmail(),
                    encoder.encode(signUpRequest.getPassword()));

            Set<String> strRoles = signUpRequest.getRole();
            Set<Role> roles = new HashSet<>();

            if (strRoles == null) {
                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
            } else {
                strRoles.forEach(role -> {
                    switch (role) {
                        case "admin" -> {
                            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(adminRole);
                        }
                        case "mod" -> {
                            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(modRole);
                        }
                        default -> {
                            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                            roles.add(userRole);
                        }
                    }
                });
            }

            user.setRoles(roles);
            userRepository.save(user);

            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
        }catch (Exception ex){
            return ResponseEntity.internalServerError()
                    .body(new MessageResponse("Internal Error: "+ex.getMessage()));
        }
    }

    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        try{
            Cookie[] cookies = request.getCookies();
            String accessToken = null;
            if (cookies == null) {
                return ResponseEntity.internalServerError().body(new MessageResponse("Some how you dont have cookie"));
            }
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("AccessToken")) {
                    accessToken = cookie.getValue();
                    break;
                }
            }
            Claims claims = jwtUtils.getPayloadFromJwtToken(accessToken);
            Long _userId = claims.get("id",Long.class);
            refreshTokenService.deleteByUserId(_userId);
            SecurityContextHolder.clearContext();
            return ResponseEntity.ok(new MessageResponse("Log out successful!"));
        }catch (Exception ex){
            return ResponseEntity.internalServerError()
                    .body(new MessageResponse("Internal Error: "+ex.getMessage()));
        }
    }

    public ResponseEntity<?> updateUser(UpdateUser updateUser){
        try {
            //check mail
            if (updateUser==null) {
                return ResponseEntity.badRequest()
                        .body(new MessageResponse("Error: You dont have any info!"));
            }
            User user = User.builder()
                    .id(updateUser.getId())
                    .fullName(updateUser.getFullName())
                    .roles(updateUser.getRole())
                    .phone(updateUser.getPhone())
                    .address(updateUser.getAddress())
                    .avatar(updateUser.getAvatar())
                    .build();
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }catch (Exception ex){
            return ResponseEntity.internalServerError()
                    .body(new MessageResponse("Internal Error: "+ex.getMessage()));
        }
    }

    public ResponseEntity<?> refreshtoken(TokenRefreshRequest request) {
        try{
            String requestRefreshToken = request.getRefreshToken();

            return refreshTokenService.findByToken(requestRefreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(refreshToken -> refreshToken.getUser())
                    .map(user -> {
                        String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                        return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                    })
                    .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                            "Refresh token is not in database!"));
        }catch (Exception ex){
            return ResponseEntity.internalServerError()
                    .body(new MessageResponse("Internal Error: "+ex.getMessage()));
        }
    }
}
