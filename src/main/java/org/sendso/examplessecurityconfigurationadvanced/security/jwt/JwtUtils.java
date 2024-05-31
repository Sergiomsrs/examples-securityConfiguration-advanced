package org.sendso.examplessecurityconfigurationadvanced.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtils {
    @Value("${jwt.secret.key}")
    private String secretKey;
    @Value("${jwt.time.expiration}")
    private String timeExpiration;

    // Generar Token
    public String generarAccesToken(String username) {
        try {
            long expirationTime = Long.parseLong(timeExpiration);
            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                    .signWith(getSignatureKey(), SignatureAlgorithm.HS256)
                    .compact();
        } catch (NumberFormatException e) {
            log.error("Error parseando el tiempo de expiración: " + e.getMessage());
            throw new RuntimeException("Error parseando el tiempo de expiración", e);
        } catch (Exception e) {
            log.error("Error generando el token: " + e.getMessage());
            throw new RuntimeException("Error generando el token", e);
        }
    }

    // Validar el token de acceso
    public boolean isTokenValid(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignatureKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return true;
        } catch (Exception e) {
            log.error("Token inválido, error: " + e.getMessage());
            return false;
        }
    }

    // Obtener un solo claim
    public <T> T getClaims(String token, Function<Claims, T> claimsTFunction) {
        Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    // Obtener el username del token
    public String getUsernameFromToken(String token) {
        return getClaims(token, Claims::getSubject);
    }

    // Obtener todos los claims del token
    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignatureKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Obtener firma del token
    public Key getSignatureKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secretKey);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            log.error("Error obteniendo la clave de firma: " + e.getMessage());
            throw new RuntimeException("Error obteniendo la clave de firma", e);
        }
    }
}