package com.example.firstappspringsecurity.security;

import com.example.firstappspringsecurity.entities.UserInfo;
import com.example.firstappspringsecurity.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

@Configuration
@RequiredArgsConstructor
public class UserInfoDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository ;
    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        Optional<UserInfo> userInfo = userRepository.findByEmail(userEmail);
        return userInfo.map(UserInfoDetails::new)
                .orElseThrow(
                        ()->new UsernameNotFoundException("user not found")
                );
    }
}
