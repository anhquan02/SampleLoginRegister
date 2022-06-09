package com.example.authentication.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.authentication.repositories.IUserRepository;
import com.example.authentication.domain.Role;
import com.example.authentication.domain.User;
import com.example.authentication.repositories.IRoleRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final IUserRepository userRepository;
    private final IRoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public User saveUser(String username, String password, String fullname, String email) {

        User user = new User(null, username, password, email, fullname, new ArrayList<>());
        user.setPassword(this.passwordEncoder.encode(password));
        return this.userRepository.save(user);
    }

    public Role saveRole(Role role) {
        return this.roleRepository.save(role);
    }

    public void addRoleToUser(String username, String roleName) {
        User user = this.userRepository.findByUsername(username);
        Role role = this.roleRepository.findByName(roleName);
        user.getRoles().add(role);
        this.userRepository.save(user);
    }

    public User getUser(String username) {
        return this.userRepository.findByUsername(username);
    }

    public List<User> getUsers() {
        return this.userRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = this.userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found in database");
        } else {

        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                authorities);
    }

}
