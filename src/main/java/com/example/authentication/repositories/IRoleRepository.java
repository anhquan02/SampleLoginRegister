package com.example.authentication.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authentication.domain.Role;

public interface IRoleRepository extends JpaRepository<Role,Long>{
    
    Role findByName(String name);

}
