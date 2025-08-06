package com.example.spring.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;

@Service
public class DHKeyService {
    private final KeyPair serverKeyPair;
    private static final String CURVE_NAME = "secp256r1";
    private static final int GCM_IV_LENGTH = 16;
    private static final int GCM_TAG_LENGTH = 128;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public DHKeyService() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
        keyPairGen.initialize(ecSpec);
        this.serverKeyPair = keyPairGen.generateKeyPair();
    }

    public String getServerPublicKey() {
        return Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
    }

    public SecretKey generateSharedSecret(String clientPublicKeyBase64) {
        try {
            byte[] clientPublicKeyBytes = Base64.getDecoder().decode(clientPublicKeyBase64);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");

            PublicKey clientPublicKey;
            try {
                X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(clientPublicKeyBytes);
                clientPublicKey = keyFactory.generatePublic(x509Spec);
            } catch (InvalidKeySpecException e) {
                // Handle raw format if X509 fails
                if (clientPublicKeyBytes[0] != 0x04) {
                    throw new IllegalArgumentException("Expected uncompressed public key format");
                }

                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(CURVE_NAME));
                ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);

                byte[] xBytes = new byte[32];
                byte[] yBytes = new byte[32];
                System.arraycopy(clientPublicKeyBytes, 1, xBytes, 0, 32);
                System.arraycopy(clientPublicKeyBytes, 33, yBytes, 0, 32);

                ECPoint point = new ECPoint(
                        new java.math.BigInteger(1, xBytes),
                        new java.math.BigInteger(1, yBytes)
                );

                ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecParameters);
                clientPublicKey = keyFactory.generatePublic(pubKeySpec);
            }

            // Generate initial shared secret
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(serverKeyPair.getPrivate());
            keyAgreement.doPhase(clientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Use HKDF to derive the key (to match Node.js implementation)
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            // Empty salt and info to match Node.js
            hkdf.init(new HKDFParameters(sharedSecret, new byte[0], new byte[0]));
            
            byte[] derivedKey = new byte[32];  // 32 bytes for AES-256
            hkdf.generateBytes(derivedKey, 0, 32);

            return new SecretKeySpec(derivedKey, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate shared secret: " + e.getMessage(), e);
        }
    }

    public Map<String, String> encrypt(String plaintext, SecretKey key) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

            // Split the ciphertext and auth tag
            int authTagOffset = ciphertext.length - (GCM_TAG_LENGTH / 8);
            byte[] encryptedData = new byte[authTagOffset];
            byte[] authTag = new byte[GCM_TAG_LENGTH / 8];
            System.arraycopy(ciphertext, 0, encryptedData, 0, authTagOffset);
            System.arraycopy(ciphertext, authTagOffset, authTag, 0, GCM_TAG_LENGTH / 8);

            Map<String, String> result = new HashMap<>();
            result.put("encrypted", Base64.getEncoder().encodeToString(encryptedData));
            result.put("iv", Base64.getEncoder().encodeToString(iv));
            result.put("authTag", Base64.getEncoder().encodeToString(authTag));

            return result;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(Map<String, String> encryptedData, SecretKey key) {
        try {
            byte[] iv = Base64.getDecoder().decode(encryptedData.get("iv"));
            byte[] ciphertext = Base64.getDecoder().decode(encryptedData.get("encrypted"));
            byte[] authTag = Base64.getDecoder().decode(encryptedData.get("authTag"));

            // Combine ciphertext and auth tag
            byte[] combined = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(authTag, 0, combined, ciphertext.length, authTag.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            byte[] plaintext = cipher.doFinal(combined);
            return new String(plaintext);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}