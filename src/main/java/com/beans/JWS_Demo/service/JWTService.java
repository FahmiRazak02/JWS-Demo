package com.beans.JWS_Demo.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
public class JWTService {

    // Load RSA Private Key
    public PrivateKey loadPrivateKey(String filename) throws Exception {
        String keyPem = new String(Files.readAllBytes(Paths.get(filename)))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(keyPem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    public String generateJwt(String payloadJson, String key, PrivateKey privateKey) throws Exception {
        var currDateTime = new Date().getTime();

        // Generate businessMessageId
        String businessMessageId = UUID.randomUUID().toString();

        String hashedPayload = DigestUtils.sha256Hex(payloadJson);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("BOEEMYK1")
                .issueTime(new Date(currDateTime))
                .expirationTime(new Date(currDateTime + 300_000))  // expires in 5 minutes
                .jwtID(businessMessageId)
                .claim("key", key)
                .claim("ds", hashedPayload)
                .build();

        // Create the signer with private key
        RSASSASigner signer = new RSASSASigner(privateKey);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }
}
