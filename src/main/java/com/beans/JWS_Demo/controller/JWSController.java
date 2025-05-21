package com.beans.JWS_Demo.controller;

import com.beans.JWS_Demo.dto.JWSRequestDTO;
import com.beans.JWS_Demo.dto.JWSVerifyDTO;
import com.beans.JWS_Demo.service.JWSService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PrivateKey;
import java.security.PublicKey;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class JWSController {

    private final JWSService jwsService;

    @PostMapping("/jws/generate")
    public ResponseEntity<?> generateJWS (@RequestBody JWSRequestDTO JWSRequestDTO) throws Exception {
        PrivateKey privateKey = jwsService.loadPrivateKey("private_key.pem");

        String jwsToken;
        if (privateKey != null){
            jwsToken = jwsService.generateJwt(JWSRequestDTO.getPayloadJson(), JWSRequestDTO.getKey(), privateKey);
        }
        else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Private key is null");
        }

        return ResponseEntity.ok()
                .body(jwsToken);

    }

    @PostMapping("/jws/verify")
    public ResponseEntity<?> verifyJWS(@RequestBody JWSVerifyDTO token) throws Exception {
        PublicKey publicKey = jwsService.loadPublicKey("public_key.pem");

        boolean verified;
        if (publicKey != null){
            verified = jwsService.verifyJws(token.getToken(), publicKey);
        }else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Public key is null");
        }

        return verified? ResponseEntity.ok().body("Token is valid") : ResponseEntity.badRequest().body("Token invalid");
    }
}
