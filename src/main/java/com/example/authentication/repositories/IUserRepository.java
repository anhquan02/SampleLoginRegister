package com.example.authentication.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authentication.domain.User;

public interface IUserRepository extends JpaRepository<User, Long>{

    User findByUsername(String username);    
    
}
