/**
 * 10.3 evening
 * https://github.com/henrychen222/Market-Backend/blob/master/src/main/java/com/itlize/marketBackend/Util/JWTProvider.java
 */
package com.example.security.JWT;

import org.springframework.beans.factory.annotation.Value;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTProvider {
    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey = "secret";

    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds = 3600000; // 1h

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);

        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public static void main(String args[]) {
        JWTProvider jwtProvider = new JWTProvider();

        //test JWT token creation: Encryption process
        List<String> roles = new ArrayList<String>();
        String username = "weichen";
        roles.add("buyer");
        roles.add("manufacturer");
        System.out.println(jwtProvider.createToken(username, roles));
    }


}
