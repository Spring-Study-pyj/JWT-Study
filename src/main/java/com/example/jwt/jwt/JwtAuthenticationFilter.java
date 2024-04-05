package com.example.jwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    String[] noAuthenticationUrlList = {"/login","/register"};
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("필터 동작함.");
        if(!noAuthenticate(request))
        {

            try {

                String token = jwtService.parseBearerToken(request);

                // 토큰 검증하기 JWT이므로 인가 서버에 요청하지 않아도됨
                jwtService.validateToken(token, request);
                // setContext 에 인증객체 저장하기.
                Authentication authentication = jwtService.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                System.out.println(authentication.getAuthorities());

            }catch (Exception e) {
            }
            //엑세스 토큰

        }
        filterChain.doFilter(request,response);
    }

    private boolean noAuthenticate(HttpServletRequest request) {

        String requestUri = request.getRequestURI();

        for(String uri: noAuthenticationUrlList){
            if(requestUri.contains(uri))
                return true;
        }

        return false;
    }
}
