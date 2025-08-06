// TokenService.java
package com.example.spring.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Service
public class TokenService {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String PRIVATE_KEY_FILE = "token_private_key.pem";
    private static final String PUBLIC_KEY_FILE = "token_public_key.pem";
    @PostConstruct
    public void init() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            if (!keysExist()) {
                generateKeyPair();
            } else {
                loadKeys();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize RSA keys", e);
        }
    }

    private boolean keysExist() {
        return new File(PRIVATE_KEY_FILE).exists() && new File(PUBLIC_KEY_FILE).exists();
    }

    private void generateKeyPair() throws Exception {
        // Use Bouncy Castle's key generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        // Save keys in PEM format
        savePemKey(PRIVATE_KEY_FILE, "Token RSA PRIVATE KEY", privateKey.getEncoded());
        savePemKey(PUBLIC_KEY_FILE, "Token RSA PUBLIC KEY", publicKey.getEncoded());
    }

    private void savePemKey(String fileName, String description, byte[] key) throws IOException {
        try (PemWriter pemWriter = new PemWriter(new FileWriter(fileName))) {
            PemObject pemObject = new PemObject(description, key);
            pemWriter.writeObject(pemObject);
        }
    }

    private void loadKeys() throws Exception {
        // Load private key
        try (PemReader pemReader = new PemReader(new FileReader(PRIVATE_KEY_FILE))) {
            PemObject pemObject = pemReader.readPemObject();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        }

        // Load public key
        try (PemReader pemReader = new PemReader(new FileReader(PUBLIC_KEY_FILE))) {
            PemObject pemObject = pemReader.readPemObject();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pemObject.getContent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            publicKey = keyFactory.generatePublic(publicKeySpec);
        }
    }

    public String signToken(Map<String, Object> tokenData) {
        try {
            // Convert token data to JSON string
            ObjectMapper mapper = new ObjectMapper();
            String tokenJson = mapper.writeValueAsString(tokenData);

            // Create signature using Bouncy Castle provider
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, "BC");
            signature.initSign(privateKey);
            signature.update(tokenJson.getBytes());

            byte[] signatureBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);

        } catch (Exception e) {
            throw new RuntimeException("Error signing token", e);
        }
    }

    public String getPublicKeyAsPem() {
        try {
            StringWriter stringWriter = new StringWriter();
            try (PemWriter pemWriter = new PemWriter(stringWriter)) {
                PemObject pemObject = new PemObject("Token RSA PUBLIC KEY", publicKey.getEncoded());
                pemWriter.writeObject(pemObject);
            }
            return stringWriter.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error exporting Token public key", e);
        }
    }
}
