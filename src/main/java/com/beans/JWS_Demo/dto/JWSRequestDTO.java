package com.beans.JWS_Demo.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class JWSRequestDTO {

    private String payloadJson;
    private String key;
}
