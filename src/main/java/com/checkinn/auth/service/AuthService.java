package com.checkinn.auth.service;

import com.checkinn.auth.dto.RegisterRequest;
import com.checkinn.auth.dto.UpdateUserRequest;
import com.checkinn.auth.dto.UserResponse;
import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import com.checkinn.auth.repository.UserRepository;
import com.checkinn.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public String login(String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmailAndAtivoTrue(email);

        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Usuário não encontrado.");
        }

        User user = optionalUser.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Senha inválida.");
        }

        return jwtUtil.generateToken(user);
    }

    public User register(RegisterRequest request) {
        if (userRepository.findByEmailAndAtivoTrue(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email já cadastrado.");
        }

        User user = User.builder()
                .nome(request.getNome())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .funcao(request.getFuncao())
                .ativo(request.getAtivo() != null ? request.getAtivo() : true)
                .build();

        return userRepository.save(user);
    }

    public List<UserResponse> listAll() {
        return userRepository.findAll().stream()
                .map(user -> new UserResponse(
                        user.getId(),
                        user.getNome(),
                        user.getEmail(),
                        user.getRole(),
                        user.getFuncao()
                ))
                .toList();
    }

    public Page<User> findUsers(String nome, String email, String role, Pageable pageable) {
        if (nome != null && !nome.isBlank()) {
            return userRepository.findByAtivoTrueAndNomeContainingIgnoreCase(nome, pageable);
        }

        if (email != null && !email.isBlank()) {
            return userRepository.findByAtivoTrueAndEmailContainingIgnoreCase(email, pageable);
        }

        if (role != null && !role.isBlank()) {
            return userRepository.findByAtivoTrueAndRole(Role.valueOf(role.toUpperCase()), pageable);
        }

        return userRepository.findByAtivoTrue(pageable);
    }

    public User updateUser(Long id, UpdateUserRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (request.nome() != null && !request.nome().isBlank())
            user.setNome(request.nome());

        if (request.funcao() != null && !request.funcao().isBlank())
            user.setFuncao(request.funcao());

        if (request.password() != null && !request.password().isBlank())
            user.setPassword(passwordEncoder.encode(request.password()));

        if (request.role() != null)
            user.setRole(request.role());

        return userRepository.save(user);
    }

    public void softDeleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        user.setAtivo(false);
        userRepository.save(user);
    }
}
