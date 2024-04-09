package vn.botstore.code.user.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import vn.botstore.code.user.service.UserDetailsImpl;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${linh.app.jwtSecret}")
    private String jwtSecret;

    @Value("${linh.app.jwtExpirationMs}")
    public int jwtExpirationMs;


    // Gen jwt TOKEN
    public String generateJwtToken(Authentication authentication) {
        // Lấy thông tin chi tiết của người dùng đã được xác thực
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        Long userId = userPrincipal.getId();
        Boolean is_admin= false;
        if (roles.contains("ROLE_ADMIN")){
            is_admin = true;
        }
//        return generateTokenFromUsername((userPrincipal.getUsername()));
//        return generateTokenWithNameAndRole((userPrincipal.getUsername()),roles,userId);
        return generateTokenWithNameAndRoleAndAdmin((userPrincipal.getUsername()),roles,userId,is_admin);
    }
    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateTokenWithNameAndRole(String username, List<String> role, Long id) {
        return Jwts.builder()
                .subject(username)
                .claim("role",role)
                .claim("id",id)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateTokenWithNameAndRoleAndAdmin(String username, List<String> role, Long id,Boolean isAdmin) {
        return Jwts.builder()
                .subject(username)
                .claim("role",role)
                .claim("id",id)
                .claim("isAdmin",isAdmin)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
    public Claims getPayloadFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
