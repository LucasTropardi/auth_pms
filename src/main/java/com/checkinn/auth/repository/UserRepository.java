package com.checkinn.auth.repository;

import com.checkinn.auth.model.Role;
import com.checkinn.auth.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmailAndAtivoTrue(String email);

    List<User> findByAtivoTrue();

    Page<User> findByAtivoTrue(Pageable pageable);

    Page<User> findByAtivoTrueAndNomeContainingIgnoreCase(String nome, Pageable pageable);

    Page<User> findByAtivoTrueAndEmailContainingIgnoreCase(String email, Pageable pageable);

    Page<User> findByAtivoTrueAndRole(Role role, Pageable pageable);
}
