package com.example.jwt.domain.dto;

public record RegisterRequest(
        String userName,
        String password
) {
}
