package com.checkinn.auth.dto;

import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserResponse {
    private Long id;
    private String nome;     // novo
    private String email;
    private Role role;
    private String funcao;   // novo

    public UserResponse(User updatedUser) {
    }

    public static UserResponse fromUser(User user) {
        return new UserResponse(
                user.getId(),
                user.getNome(),
                user.getEmail(),
                user.getRole(),
                user.getFuncao()
        );
    }
}

