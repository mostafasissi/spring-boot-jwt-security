package com.example.firstappspringsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@Data
@RequiredArgsConstructor
@Builder
public class JwtService {
    public static final String SECRET_KEY = "42444a4f39303739715846614365673230624376717348715654454a63506856";
    public String extractUserEmail(String token) {

        return extractClaim(token , Claims::getSubject) ; // the subjet reprents the email
    }
    public String generateToken(
            Map<String , Object> extratClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extratClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey() , SignatureAlgorithm.HS256)
                .compact();
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>() , userDetails);
    }
    public boolean isTokenValidat(String token , UserDetails userDetails){
        final String username = extractUserEmail(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExperation(token).before(new Date()); // the experation date should be before the current date
    }

    private Date extractExperation(String token) {
        return extractClaim(token , Claims::getExpiration);
    }

    public <T> T extractClaim(String token , Function<Claims , T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    public Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
