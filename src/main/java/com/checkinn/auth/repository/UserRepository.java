package com.checkinn.auth.repository;

import com.checkinn.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmailAndAtivoTrue(String email);

    List<User> findByAtivoTrue();
}
