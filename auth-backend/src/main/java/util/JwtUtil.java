package util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtUtil {
    private static final String SECRET = System.getenv("JWT_SECRET");
    private static final Algorithm algorithm = Algorithm.HMAC256(SECRET);

    public static String generateToken(String email) {
        return JWT.create()
                .withSubject(email)
                .sign(algorithm);
    }

    public static String verifyToken(String token) throws JWTVerificationException {
        DecodedJWT jwt = JWT.require(algorithm)
                .build()
                .verify(token);
        return jwt.getSubject();
    }
}