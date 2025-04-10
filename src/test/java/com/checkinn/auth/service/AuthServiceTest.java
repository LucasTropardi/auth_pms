package com.checkinn.auth.service;

import com.checkinn.auth.dto.RegisterRequest;
import com.checkinn.auth.dto.UpdateUserRequest;
import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import com.checkinn.auth.repository.UserRepository;
import com.checkinn.auth.security.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

class AuthServiceTest {

    private AuthService authService;
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtUtil jwtUtil;

    @BeforeEach
    void setup() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        jwtUtil = mock(JwtUtil.class);
        authService = new AuthService(userRepository, passwordEncoder, jwtUtil);
    }

    @Test
    void shouldRegisterNewUser() {
        RegisterRequest request = new RegisterRequest();
        request.setNome("Lucas");
        request.setEmail("lucas@email.com");
        request.setPassword("123456");
        request.setFuncao("Dev");
        request.setRole(Role.USER);

        when(userRepository.findByEmailAndAtivoTrue("lucas@email.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("123456")).thenReturn("encoded");

        authService.register(request);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        User user = captor.getValue();
        assertThat(user.getNome()).isEqualTo("Lucas");
        assertThat(user.getEmail()).isEqualTo("lucas@email.com");
        assertThat(user.getPassword()).isEqualTo("encoded");
        assertThat(user.getRole()).isEqualTo(Role.USER);
        assertThat(user.getFuncao()).isEqualTo("Dev");
        assertThat(user.isAtivo()).isTrue();
    }

    @Test
    void shouldLoginWithValidCredentials() {
        String email = "lucas@example.com";
        String rawPassword = "123456";
        String encodedPassword = "encoded-password";

        User user = User.builder()
                .id(1L)
                .nome("Lucas")
                .email(email)
                .password(encodedPassword)
                .role(Role.USER)
                .funcao("Tester")
                .ativo(true)
                .build();

        when(userRepository.findByEmailAndAtivoTrue(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(rawPassword, encodedPassword)).thenReturn(true);
        when(jwtUtil.generateToken(user)).thenReturn("mocked-jwt-token");

        String token = authService.login(email, rawPassword);

        assertEquals("mocked-jwt-token", token);
    }

    @Test
    void shouldThrowWhenUserNotFoundOnLogin() {
        // Arrange
        String email = "notfound@email.com";
        when(userRepository.findByEmailAndAtivoTrue(email)).thenReturn(Optional.empty());

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.login(email, "123456");
        });

        assertEquals("Usuário não encontrado.", exception.getMessage());
    }

    @Test
    void shouldThrowWhenPasswordIsIncorrect() {
        // Arrange
        String email = "login@email.com";
        User user = User.builder()
                .id(1L)
                .email(email)
                .password(passwordEncoder.encode("senha-correta"))
                .role(Role.USER)
                .nome("Login Test")
                .ativo(true)
                .build();

        when(userRepository.findByEmailAndAtivoTrue(email)).thenReturn(Optional.of(user));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            authService.login(email, "senha-errada");
        });

        assertEquals("Senha inválida.", exception.getMessage());
    }

    @Test
    void shouldUpdateUserFields() {
        Long userId = 1L;
        User existingUser = User.builder()
                .id(userId)
                .nome("Original")
                .email("email@email.com")
                .password("old-pass")
                .funcao("Analista")
                .role(Role.USER)
                .ativo(true)
                .build();

        UpdateUserRequest request = new UpdateUserRequest("Novo Nome", "Nova Função", "novaSenha", Role.ADMIN);

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.encode("novaSenha")).thenReturn("encodedNovaSenha");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0)); // importante!

        User updated = authService.updateUser(userId, request);

        assertEquals("Novo Nome", updated.getNome());
        assertEquals("Nova Função", updated.getFuncao());
        assertEquals("encodedNovaSenha", updated.getPassword());
        assertEquals(Role.ADMIN, updated.getRole());
        verify(userRepository).save(updated);
    }

    @Test
    void shouldSoftDeleteUser() {
        Long userId = 1L;
        User user = User.builder()
                .id(userId)
                .nome("Lucas")
                .email("lucas@email.com")
                .ativo(true)
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        authService.softDeleteUser(userId);

        assertThat(user.isAtivo()).isFalse();
        verify(userRepository).save(user);
    }

    @Test
    void shouldListAllUsers() {
        User user1 = User.builder().id(1L).nome("Lucas").email("a@a.com").funcao("Dev").role(Role.USER).build();
        User user2 = User.builder().id(2L).nome("Ana").email("b@b.com").funcao("QA").role(Role.ADMIN).build();

        when(userRepository.findAll()).thenReturn(List.of(user1, user2));

        var result = authService.listAll();

        assertThat(result).hasSize(2);
        assertEquals("Lucas", result.get(0).getNome());
        assertEquals("Ana", result.get(1).getNome());
    }

    @Test
    void shouldUpdateOnlyNomeAndIgnoreNullOrBlankFields() {
        Long userId = 1L;
        User existingUser = User.builder()
                .id(userId)
                .nome("Lucas")
                .email("lucas@email.com")
                .password("oldpass")
                .funcao("Analista")
                .role(Role.USER)
                .ativo(true)
                .build();

        UpdateUserRequest request = new UpdateUserRequest("Lucas Atualizado", null, "   ", null); // funcao nula, senha em branco, role nula

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User updated = authService.updateUser(userId, request);

        assertEquals("Lucas Atualizado", updated.getNome());
        assertEquals("Analista", updated.getFuncao()); // não muda
        assertEquals("oldpass", updated.getPassword()); // não muda
        assertEquals(Role.USER, updated.getRole()); // não muda
    }

    @Test
    void shouldThrowWhenSoftDeletingNonExistingUser() {
        Long invalidId = 99L;
        when(userRepository.findById(invalidId)).thenReturn(Optional.empty());

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            authService.softDeleteUser(invalidId);
        });

        assertEquals("Usuário não encontrado", ex.getMessage());
        verify(userRepository, never()).save(any());
    }

    @Test
    void shouldThrowWhenRegisteringWithExistingEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setNome("Lucas");
        request.setEmail("lucas@email.com");
        request.setPassword("123456");
        request.setFuncao("Dev");

        when(userRepository.findByEmailAndAtivoTrue("lucas@email.com"))
                .thenReturn(Optional.of(new User()));

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            authService.register(request);
        });

        assertEquals("Email já cadastrado.", ex.getMessage());
        verify(userRepository, never()).save(any());
    }

}
