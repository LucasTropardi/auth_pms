package com.checkinn.auth.security;

import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.security.Key;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private final String secret = "12345678901234567890123456789012"; // 32 chars (mínimo para HMAC SHA)
    private final long expiration = 3600000L; // 1 hora

    @BeforeEach
    void setUp() throws Exception {
        jwtUtil = new JwtUtil();

        Field secretField = JwtUtil.class.getDeclaredField("jwtSecret");
        secretField.setAccessible(true);
        secretField.set(jwtUtil, secret);

        Field expirationField = JwtUtil.class.getDeclaredField("jwtExpiration");
        expirationField.setAccessible(true);
        expirationField.set(jwtUtil, expiration);
    }

    @Test
    void shouldGenerateValidToken() {
        User user = User.builder()
                .id(1L)
                .email("teste@email.com")
                .role(Role.USER)
                .build();

        String token = jwtUtil.generateToken(user);
        assertNotNull(token);

        // Validar conteúdo do token
        Key key = Keys.hmacShaKeyFor(secret.getBytes());
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();

        assertEquals("1", claims.getSubject());
        assertEquals("teste@email.com", claims.get("email", String.class));
        assertEquals("USER", claims.get("role", String.class));
        assertTrue(claims.getExpiration().after(new Date()));
    }

    @Test
    void shouldThrowExceptionForExpiredToken() {
        User user = User.builder()
                .id(2L)
                .email("expirado@email.com")
                .role(Role.USER)
                .build();

        // Token expirado: validade de -1 minuto
        Date now = new Date();
        Date expiredDate = new Date(now.getTime() - 60000); // 1 minuto atrás
        Key key = Keys.hmacShaKeyFor(secret.getBytes());

        String token = Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("role", user.getRole().name())
                .setIssuedAt(now)
                .setExpiration(expiredDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        assertThrows(io.jsonwebtoken.ExpiredJwtException.class, () -> {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        });
    }

    @Test
    void shouldThrowExceptionForInvalidSignature() {
        User user = User.builder()
                .id(3L)
                .email("assinatura@email.com")
                .role(Role.ADMIN)
                .build();

        // Gera token com uma chave falsa
        String fakeSecret = "abcdefghijklmnopqrstuvxyz12345678";
        Key fakeKey = Keys.hmacShaKeyFor(fakeSecret.getBytes());

        String token = Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("role", user.getRole().name())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 360000))
                .signWith(fakeKey, SignatureAlgorithm.HS256)
                .compact();

        // Tenta validar com a chave correta (e vai falhar)
        Key key = Keys.hmacShaKeyFor(secret.getBytes());

        assertThrows(io.jsonwebtoken.security.SignatureException.class, () -> {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
        });
    }

    @Test
    void shouldThrowExceptionForMalformedToken() {
        String malformedToken = "isso-nao-e-um-token-valido";

        Key key = Keys.hmacShaKeyFor(secret.getBytes());

        assertThrows(io.jsonwebtoken.MalformedJwtException.class, () -> {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(malformedToken);
        });
    }

}
