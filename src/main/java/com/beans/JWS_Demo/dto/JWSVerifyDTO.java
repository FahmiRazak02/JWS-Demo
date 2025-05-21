package com.beans.JWS_Demo.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Data
public class JWSVerifyDTO {

    private String token;
}
