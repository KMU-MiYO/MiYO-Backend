package io.github.herbpot.miyobackend.domain.user.service;

import io.github.herbpot.miyobackend.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUserId(username)
                .map(user -> new User(user.getUserId(), user.getPassword(), new ArrayList<>()))
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + username));
    }
}
