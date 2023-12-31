package com.example.firstappspringsecurity.repositories;

import com.example.firstappspringsecurity.entities.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserInfo, Long> {
    Optional<UserInfo> findByEmail(String userEmail);
}
