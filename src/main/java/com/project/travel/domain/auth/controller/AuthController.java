package com.project.travel.domain.auth.controller;

import com.project.travel.domain.auth.dto.request.AuthReissueRequest;
import com.project.travel.domain.auth.dto.request.AuthSignInRequest;
import com.project.travel.domain.auth.dto.request.AuthSignUpRequest;
import com.project.travel.domain.auth.dto.response.AuthReissueResponse;
import com.project.travel.domain.auth.dto.response.AuthSignInResponse;
import com.project.travel.domain.auth.dto.response.AuthSignUpResponse;
import com.project.travel.domain.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthSignUpResponse> signup(
            @RequestBody @Valid AuthSignUpRequest request
    ) {
        AuthSignUpResponse response = authService.signUp(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthSignInResponse> signin(
            @RequestBody @Valid AuthSignInRequest request
    ) {
        AuthSignInResponse response = authService.signIn(request);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(response);
    }

    @PostMapping("/reissue")
    public ResponseEntity<AuthReissueResponse> reissue(
            @RequestBody @Valid AuthReissueRequest request
    ) {
        AuthReissueResponse response = authService.reissue(request);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(response);
    }
}
