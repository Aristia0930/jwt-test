package org.example.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@Component
public class MyFilter extends OncePerRequestFilter {
    //접속시 addFilterBefore 또는 addFilterAfter 에 걸어서 사용한다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("필터1");
        HttpServletRequest req=(HttpServletRequest) request;
        HttpServletResponse res=(HttpServletResponse) response;
        if(req.getMethod().equals("POST")){
            System.out.println("post 요청");
            String headerAuth = req.getHeader("Authorization");

            System.out.println(headerAuth);

            if(headerAuth.equals("hi")){
                filterChain.doFilter(req,res);
            }
            else{
                PrintWriter out = res.getWriter(); // 응답에 보내주는거
                out.println("인증안됨");
                return;
            }
        }


        filterChain.doFilter(req,res);

    }
}
