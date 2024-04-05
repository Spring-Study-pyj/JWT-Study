package com.example.jwt.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {


    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, org.springframework.security.access.AccessDeniedException accessDeniedException) throws IOException, ServletException {
        System.out.println("권한 없음.");
        request.setAttribute("error","권한없는 접근입니다.");
        ObjectMapper ob = new ObjectMapper();
        ResponseEntity<?> responseEntity = ResponseEntity.status(401)
                .body("권한없는 접근입니다.");
        response.getWriter().println(ob.writeValueAsString(responseEntity));
    }
}