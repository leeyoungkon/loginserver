package com.example.loginserver.controller;

import com.example.loginserver.dto.AuthResponse;
import com.example.loginserver.dto.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.Optional;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class LoginController {

    private final RestClient restClient;

    @Value("${auth.server.url}")
    private String authServerUrl;

    @Value("${auth.server.register.url}")
    private String authServerRegisterUrl;

    @Value("${ingress.url}")
    private String ingressUrl;

    private Optional<String> resolveFallbackAuthLoginUrl() {
        if (authServerUrl == null) {
            return Optional.empty();
        }

        if (authServerUrl.endsWith("/api/auth/login")) {
            return Optional.of(authServerUrl.replace("/api/auth/login", "/api/login"));
        }

        return Optional.empty();
    }

    private AuthResponse requestToken(LoginRequest loginRequest, String url) {
        return restClient.post()
                .uri(url)
                .contentType(MediaType.APPLICATION_JSON)
                .body(loginRequest)
                .retrieve()
                .body(AuthResponse.class);
    }

    private AuthResponse requestTokenWithFallback(LoginRequest loginRequest) {
        try {
            return requestToken(loginRequest, authServerUrl);
        } catch (RestClientResponseException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                Optional<String> fallbackUrl = resolveFallbackAuthLoginUrl();
                if (fallbackUrl.isPresent()) {
                    return requestToken(loginRequest, fallbackUrl.get());
                }
            }
            throw e;
        }
    }

    /**
     * 사용자 id/password 로그인 → Auth 서버에서 JWT 발급 → Ingress를 통해 Order 서비스 호출
     */
    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody LoginRequest loginRequest) {

        // 1. Auth 서버에 인증 요청하여 JWT 발급
        AuthResponse authResponse;
        try {
            authResponse = requestTokenWithFallback(loginRequest);
        } catch (RestClientResponseException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Authentication failed: " + e.getResponseBodyAsString());
        }

        if (authResponse == null || authResponse.getToken() == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Authentication failed: token not received");
        }

        // 2. 발급된 JWT를 Authorization 헤더에 담아 Ingress를 통해 Order 서비스 요청
        try {
            Object orderResponse = restClient.get()
                    .uri(ingressUrl + "/delivery")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + authResponse.getToken())
                    .retrieve()
                    .body(Object.class);

            return ResponseEntity.ok(orderResponse);
        } catch (RestClientResponseException e) {
            return ResponseEntity
                    .status(e.getStatusCode())
                    .body("Order service error: " + e.getResponseBodyAsString());
        }

    }

    /**
     * 사용자 id/password 로그인 → Auth 서버에서 JWT 발급 결과를 그대로 반환
     */
    @PostMapping("/login/token")
    public ResponseEntity<Object> loginForToken(@RequestBody LoginRequest loginRequest) {
        try {
            AuthResponse authResponse = requestTokenWithFallback(loginRequest);

            if (authResponse == null || authResponse.getToken() == null) {
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body("Authentication failed: token not received");
            }

            return ResponseEntity.ok(authResponse);
        } catch (RestClientResponseException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Authentication failed: " + e.getResponseBodyAsString());
        }
    }

    /**
     * 사용자 id/password 회원가입 요청 → Auth 서버를 통해 DB에 사용자 등록
     */
    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody LoginRequest loginRequest) {
        try {
            Object registerResponse = restClient.post()
                    .uri(authServerRegisterUrl)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(loginRequest)
                    .retrieve()
                    .body(Object.class);

            return ResponseEntity.status(HttpStatus.CREATED).body(registerResponse);
        } catch (RestClientResponseException e) {
            return ResponseEntity
                    .status(e.getStatusCode())
                    .body("Register failed: " + e.getResponseBodyAsString());
        }
    }

    @GetMapping("/delivery")
public ResponseEntity<Object> callDelivery(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader
) 
    {
    if (authorizationHeader == null || authorizationHeader.isBlank()) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("Missing Authorization header");
    }

    try {
        String targetUrl = ingressUrl + "/delivery/status";

        String deliveryResponse = restClient.get()
                .uri(targetUrl)
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .retrieve()
                .body(String.class);

        return ResponseEntity.ok(deliveryResponse);

    } catch (RestClientResponseException e) {
        return ResponseEntity
                .status(e.getStatusCode())
                .body("Delivery service error: " + e.getResponseBodyAsString());

    } catch (Exception e) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Delivery call exception: " + e.getClass().getName() + " - " + e.getMessage());
    }
}
}

