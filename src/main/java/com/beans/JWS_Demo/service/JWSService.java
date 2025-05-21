package com.beans.JWS_Demo.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
public class JWSService {

    // Load Private Key
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

    // Load Public Key
    public PublicKey loadPublicKey(String filename) throws Exception {
        String keyPem = new String(Files.readAllBytes(Paths.get(filename)))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(keyPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
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

    public boolean verifyJws(String token, PublicKey publicKey) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(token);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

        boolean isValid = signedJWT.verify(verifier);

        if (isValid) {
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            System.out.println("Issuer: " + claims.getIssuer());
            System.out.println("Expiration Time: " + claims.getExpirationTime());
            System.out.println("JWT ID (jti): " + claims.getJWTID());
            System.out.println("key: " + claims.getStringClaim("key"));
            System.out.println("ds: " + claims.getStringClaim("ds"));

            // Check expiration
            if (new Date().after(claims.getExpirationTime())) {
                System.out.println("Token has expired.");
                return false;
            }

            return true;
        } else {
            System.out.println("Signature verification failed.");
            return false;
        }
    }
}
