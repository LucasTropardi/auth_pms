package com.checkinn.auth.controller;

import com.checkinn.auth.dto.*;
import com.checkinn.auth.model.User;
import com.checkinn.auth.repository.UserRepository;
import com.checkinn.auth.security.AuthenticatedUser;
import com.checkinn.auth.security.JwtUtil;
import com.checkinn.auth.service.AuthService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        String token = authService.login(request.getEmail(), request.getPassword());
        return ResponseEntity.ok(new LoginResponse(token));
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = authService.register(request);
        return ResponseEntity.ok(new UserResponse(user));
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserResponse>> listUsers(
            @RequestParam(required = false) String nome,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String role,
            @PageableDefault(size = 10, sort = "id") Pageable pageable) {

        Page<User> page = authService.findUsers(nome, email, role, pageable);
        return ResponseEntity.ok(page.map(UserResponse::new));
    }

    @PutMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRequest request) {

        User user = authService.updateUser(id, request);
        return ResponseEntity.ok(new UserResponse(user));
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        authService.softDeleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    public ResponseEntity<UserResponse> me(@AuthenticationPrincipal AuthenticatedUser authUser) {
        return ResponseEntity.ok(new UserResponse(authUser.getUser()));
    }

    @GetMapping("/validate")
    public ResponseEntity<UserResponse> validateToken(@RequestHeader("Authorization") String token) {
        try {
            String jwt = token.replace("Bearer ", "");
            Claims claims = jwtUtil.parseToken(jwt);

            String email = claims.get("email", String.class);

            User user = userRepository.findByEmailAndAtivoTrue(email)
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado."));

            return ResponseEntity.ok(new UserResponse(user));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

}
