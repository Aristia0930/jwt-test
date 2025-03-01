package org.example.jwt.config;

import org.example.jwt.filter.MyFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

public class FilterConfig {
    //이렇게 해도 시큐리티 필터 체인 이보다는 느리게 동작한다. 시큐리티 커피그에 => 직접 체인을 걸우준다.


    @Bean
    public FilterRegistrationBean<MyFilter> filter1(){
        FilterRegistrationBean<MyFilter> bean = new FilterRegistrationBean<>(new MyFilter());
        bean.addUrlPatterns("/*"); //모든 요청에 대해서 적용
        bean.setOrder(0);//낮은 번호가 필터중에서 가장 먼전 실행됨
        return bean;
    }
}
