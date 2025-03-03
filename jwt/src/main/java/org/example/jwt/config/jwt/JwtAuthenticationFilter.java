package org.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.jwt.config.auth.PrincipalDetails;
import org.example.jwt.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;


//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// login 에 요청이 오면 username,password 전송하면 이 필터가 동작함
// 현재 우리는 from 로그이능ㄹ 디스에이블함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
//    private final CustomAuthenticationProvider customAuthenticationProvider;
//    private final BCryptPasswordEncoder passwordEncoder;  // BCryptPasswordEncoder 주입

    //로그인 요청하면 동작 로그인 시도를 위해 시도하는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인시도요청");
        //1. 여기서 아이디와 패스워드 확인
        try {
//            BufferedReader br=request.getReader(); //로그인 정보를 받는다  username=ssar&password=1234 이런게 나온다,.
//            //제이슨 인경우에는{
//            //    "username": "yourUsername",
//            //    "password": "yourPassword"
//            //}
//            String input=null;
//            while((input =br.readLine())!=null){
//                System.out.println(input);
//            }

            //제이슨 데이터 파싱을 위해 사용
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            System.out.println(user);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            System.out.println("JwtAuthenticationFilter : 토큰생성완료" + token);
            //2.정상인지 로그인 시도 해보는거
            //3.authenticationManager 이걸로 로그인 시도를를 하면  PrincipalDetailsService 이걸 호출 하도록한다.
            Authentication authentication = authenticationManager.authenticate(token);

//            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//            System.out.println(principalDetails.getUser().getUsername());


//            System.out.println(request.getInputStream().toString()); // 이게 유저아이디(이름)와 패스워드 가 담겨있다

            //4.PrincipalDetails 를 세션에 담고 (이걸하는 이유는 권한 권한과리르 위해) 이제 세션에 저장하는 바업ㅂ이 리턴해주는 방버 시큐리티가 대신처리해줌

            //5.jwt 토큰을 만들어서 응답을 주면 됨.
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException("로그인 요청 처리 중 오류 발생", e); // JSON 파싱 오류 시 예외 처리
        } catch (AuthenticationException e) {
            // 인증 실패 시 예외 처리
            System.out.println("🚨 AuthenticationException 발생: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized
            return null; // 인증 실패 시 null 반환 (기본적으로 Spring Security에서 처리됨)
        } catch (Exception e) {
            System.out.println("🚨 예상하지 못한 예외 발생: " + e.getMessage());
            e.printStackTrace();
            return null;
        }


    }


    //attemptAuthentication 실행후 실행되는곳 인증이 정상적으로 도달 하면 실행 됨 그렇기에 여기서 jwt 토큰을 만들어줌 요청한 사용자에게 응답으로 전성해주면됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("인증이 정상적으로 완료됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //Hash 방식 이거 말고도 rsa 방식도 존재한다.

        String jwtToken= JWT.create()
                .withSubject(principalDetails.getUsername())//토큰이름
                .withExpiresAt(new Date(System.currentTimeMillis()+(60000*10)))//만료 시간 60000 이 1분
                .withClaim("id",principalDetails.getUser().getId())
                .withClaim("username",principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("code"));//내 고유의값.

        response.addHeader("Authorization","Bearer "+jwtToken);
        //이렇게 사용자에게 jwt 토큰을 보냈으면 이제 이 토큰이 유효한지 확인하는 필터가 필요함
    }
}
