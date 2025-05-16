package com.beans.JWS_Demo.controller;

import com.beans.JWS_Demo.dto.JWTRequestDTO;
import com.beans.JWS_Demo.service.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PrivateKey;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class JWTController {

    private final JWTService jwtService;

    @PostMapping("/jws")
    public ResponseEntity<?> generateJWS (@RequestBody JWTRequestDTO jwtRequestDTO) throws Exception {
        PrivateKey privateKey = jwtService.loadPrivateKey("private_key.pem");

        String jwsToken;
        if (privateKey != null){
            jwsToken = jwtService.generateJwt(jwtRequestDTO.getPayloadJson(), jwtRequestDTO.getKey(), privateKey);
        }
        else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Private key is null");
        }

        return ResponseEntity.ok()
                .body(jwsToken);

    }
}
