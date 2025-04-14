package com.checkinn.auth.controller;

import com.checkinn.auth.dto.*;
import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import com.checkinn.auth.repository.UserRepository;
import com.checkinn.auth.security.AuthenticatedUser;
import com.checkinn.auth.security.JwtUtil;
import com.checkinn.auth.service.AuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    private AuthController authController;
    private AuthService authService;
    private JwtUtil jwtUtil;
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        authService = mock(AuthService.class);
        jwtUtil = mock(JwtUtil.class);
        userRepository = mock(UserRepository.class);

        authController = new AuthController(authService, jwtUtil, userRepository);
    }

    @Test
    void shouldRegisterUserThroughController() {
        RegisterRequest request = new RegisterRequest();
        request.setNome("Novo");
        request.setEmail("novo@email.com");
        request.setPassword("123456");
        request.setRole(Role.USER);
        request.setFuncao("Tester");

        User user = User.builder()
                .id(10L)
                .nome("Novo")
                .email("novo@email.com")
                .role(Role.USER)
                .funcao("Tester")
                .ativo(true)
                .build();

        when(authService.register(any())).thenReturn(user);

        var response = authController.register(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Novo", response.getBody().getNome());
    }

    @Test
    void shouldLoginThroughController() {
        LoginRequest request = new LoginRequest("admin@email.com", "123456");
        when(authService.login(anyString(), anyString())).thenReturn("mocked-token");

        var response = authController.login(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("mocked-token", response.getBody().getToken());
    }

    @Test
    void shouldReturnCurrentUserInfo() {
        User user = User.builder()
                .id(1L)
                .email("auth@email.com")
                .nome("Autenticado")
                .funcao("QA")
                .role(Role.ADMIN)
                .build();

        AuthenticatedUser authUser = new AuthenticatedUser(user);

        var response = authController.me(authUser);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Autenticado", response.getBody().getNome());
    }
}
