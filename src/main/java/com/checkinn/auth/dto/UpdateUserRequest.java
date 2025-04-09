package com.checkinn.auth.dto;

import com.checkinn.auth.model.Role;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(

        @Size(min = 2, max = 100, message = "Nome deve ter entre 2 e 100 caracteres")
        String nome,

        @Size(min = 2, max = 100, message = "Função deve ter entre 2 e 100 caracteres")
        String funcao,

        @Size(min = 6, message = "Senha deve ter pelo menos 6 caracteres")
        String password,

        Role role
) {}
