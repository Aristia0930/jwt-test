package org.example.jwt.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config=new CorsConfiguration();
        config.setAllowCredentials(true); //내 서버가 응답할때 제이슨을 자바스크트에서 처리할 수 있게 설정
        config.addAllowedOrigin("*"); //모든  ip 에 대한 응답 허용
        config.addAllowedHeader("*"); // 모드 헤더에 대한 응답허용
        config.addAllowedMethod("*"); // 모든 post,get,delet,path 요청에 대한 허용
        source.registerCorsConfiguration("/api/**",config);
        return new CorsFilter(source);
    }
}
