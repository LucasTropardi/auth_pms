package com.checkinn.auth.security;

import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import com.checkinn.auth.repository.UserRepository;
import com.checkinn.auth.security.AuthenticatedUser;
import com.checkinn.auth.security.JwtFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.Key;
import java.util.Date;
import java.util.Optional;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtFilterTest {

    private JwtFilter jwtFilter;
    private UserRepository userRepository;
    private final String jwtSecret = "12345678901234567890123456789012";
    private final long jwtExpiration = 3600000L;

    @BeforeEach
    void setup() throws Exception {
        SecurityContextHolder.clearContext(); // limpa autenticação anterior

        userRepository = mock(UserRepository.class);

        jwtFilter = new JwtFilter(userRepository) {
            @Override
            public void doFilterInternal(HttpServletRequest request,
                                         HttpServletResponse response,
                                         FilterChain filterChain) throws ServletException, IOException {
                super.doFilterInternal(request, response, filterChain);
            }
        };

        Field secretField = JwtFilter.class.getDeclaredField("jwtSecret");
        secretField.setAccessible(true);
        secretField.set(jwtFilter, jwtSecret);
    }

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldSetAuthenticationWithValidToken() throws ServletException, IOException {
        // Arrange
        User user = User.builder()
                .id(1L)
                .email("auth@email.com")
                .nome("Test")
                .funcao("Dev")
                .role(Role.ADMIN)
                .ativo(true)
                .build();

        when(userRepository.findByEmailAndAtivoTrue("auth@email.com")).thenReturn(Optional.of(user));

        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        String jwt = Jwts.builder()
                .setSubject("1")
                .claim("email", "auth@email.com")
                .claim("role", "ADMIN")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + jwt);
        var response = new MockHttpServletResponse();
        var filterChain = mock(FilterChain.class);

        // Act
        jwtFilter.doFilterInternal(request, response, filterChain);

        // Assert
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("auth@email.com",
                ((AuthenticatedUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRespondUnauthorizedForInvalidToken() throws ServletException, IOException {
        var request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer token-invalido");
        var response = new MockHttpServletResponse();
        var filterChain = mock(FilterChain.class);

        jwtFilter.doFilterInternal(request, response, filterChain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void shouldSkipFilterWhenNoAuthorizationHeader() throws ServletException, IOException {
        var request = new MockHttpServletRequest(); // sem Authorization
        var response = new MockHttpServletResponse();
        var filterChain = mock(FilterChain.class);

        jwtFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}
