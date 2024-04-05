package com.example.jwt.controller;

import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.domain.dto.RegisterRequest;
import com.example.jwt.jwt.JwtService;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final JwtService jwtService;
    private final UserRepository userRepository;


    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest request
            ) {
        User newUser = User.builder()
                .userId(request.userName())
                .password(request.password())
                .role(Role.ROLE_USER)
                .build();

        User u = userRepository.save(newUser);
        return ResponseEntity.ok()
                .body(u);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody RegisterRequest request
    ) {
        User user = userRepository.findByUserId(request.userName())
                .orElseThrow(() -> new RuntimeException("로그인 실패"));

        String accessToken = jwtService.issueAccessToken(user);
        return ResponseEntity.ok()
                .body(accessToken);

    }

    @GetMapping("/test")
    public String test() {
        return "success";
    }

    @GetMapping("/test2")
    public String test2() {
        return "success";
    }


}
