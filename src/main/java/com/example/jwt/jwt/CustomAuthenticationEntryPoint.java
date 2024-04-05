package com.example.jwt.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String errorName = String.valueOf(request.getAttribute("error"));
        System.out.println("인증 실패");
        System.out.println(errorName);
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        ObjectMapper ob = new ObjectMapper();

        ResponseEntity<?> responseEntity = ResponseEntity.status(401)
                .body(errorName);
        response.getWriter().println(ob.writeValueAsString(responseEntity));
    }
}
