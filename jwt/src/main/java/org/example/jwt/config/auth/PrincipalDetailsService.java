package org.example.jwt.config.auth;

import lombok.RequiredArgsConstructor;
import org.example.jwt.model.User;
import org.example.jwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


// 로그인 주소로 들어왔을대 /login
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("로그인 PrincipalDetailsService");
        User userEntity=userRepository.findByUsername(username);

        System.out.println(userEntity);



        return new PrincipalDetails(userEntity);


    }
}
