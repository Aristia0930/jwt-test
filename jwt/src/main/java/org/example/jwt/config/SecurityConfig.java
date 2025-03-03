package org.example.jwt.config;

import lombok.RequiredArgsConstructor;
//import org.example.jwt.config.auth.CustomAuthenticationProvider;
import org.example.jwt.config.jwt.JwtAuthenticationFilter;
//import org.example.jwt.filter.MyFilter;
import org.example.jwt.filter.MyFilterBefor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor //@RequiredArgsConstructor는 Lombok에서 제공하는 어노테이션으로,
                        //클래스의 final 필드 또는 @NonNull이 붙은 필드를 매개변수로 받는 생성자를 자동으로 생성해 줍니다.
public class SecurityConfig  {
    private final AuthenticationConfiguration authenticationConfiguration;


    private final CorsConfig corsConfig;
    private final MyFilterBefor myFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,AuthenticationManager authenticationManager) throws Exception {


        return http
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화 (JWT 사용 시 필요)
                .addFilterBefore(myFilter, SecurityContextHolderFilter.class) // 내가 제작한 필터가 BasicAuthenticationFilter 가등장 전에 적용된다라는 의미 이런걸 수정확인 위해서는
                //시큐리티 필터들을 순서를 확인해야한다 위처럼 사용해도 되고 Bean 을 만들어 사용할수 있다 FilterConfig 에 있음
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션 사용 안 함
                .addFilter(corsConfig.corsFilter()) //필터 적용
                .addFilterAt(new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class)
                .formLogin(form -> form.disable()) // 폼 로그인 비활성화
                .httpBasic(basic -> basic.disable()) // HTTP Basic 인증 비활성화
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/user/**").hasAnyRole("USER", "MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll() // 그 외 경로는 인증 없이 접근
                        // 가능
                )
                .build();




    }

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }




    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }


}
