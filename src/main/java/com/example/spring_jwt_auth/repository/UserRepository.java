package com.example.spring_jwt_auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.spring_jwt_auth.model.User;

public interface UserRepository extends JpaRepository<com.example.spring_jwt_auth.model.User, Integer> {
    Optional<User> findByUsername(String username);
}