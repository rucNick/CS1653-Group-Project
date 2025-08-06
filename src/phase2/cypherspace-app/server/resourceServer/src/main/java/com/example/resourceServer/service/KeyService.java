package com.example.resourceServer.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.*;
import java.util.logging.Logger;

@Service
public class KeyService {
    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private PrivateKey currentECDHPrivateKey;
    private SecretKey aesKey;
    private static final Logger logger = Logger.getLogger(KeyService.class.getName());
    private static final String KEY_STORE_PATH = "server_keystore.jks";
    private static final String KEY_STORE_PASSWORD = "asljdlaskdjiamcxiqh1@@#";
    private static final String KEY_ALIAS = "serverRSAKey";

    @PostConstruct
    public void init() {
        try {
            loadOrGenerateRSAKeys();
            logger.info("Key service initialized successfully");
        } catch (Exception e) {
            logger.severe("Failed to initialize key service: " + e.getMessage());
            throw new RuntimeException("Failed to initialize key service", e);
        }
    }

    private void loadOrGenerateRSAKeys() {
        try {
            File keyStoreFile = new File(KEY_STORE_PATH);
            if (keyStoreFile.exists()) {
                // Load existing keys
                KeyStore keyStore = KeyStore.getInstance("JKS");
                try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
                    keyStore.load(fis, KEY_STORE_PASSWORD.toCharArray());

                    // Get private key
                    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
                        keyStore.getEntry(KEY_ALIAS,
                            new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
                    rsaPrivateKey = pkEntry.getPrivateKey();
                    rsaPublicKey = pkEntry.getCertificate().getPublicKey();

                    logger.info("Loaded existing RSA keys from keystore");
                }
            } else {
                // Generate new keys
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();
                rsaPrivateKey = pair.getPrivate();
                rsaPublicKey = pair.getPublic();

                // Create keystore and store keys
                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStore.load(null, null);

                // Create self-signed certificate
                X509Certificate[] certChain = createSelfSignedCertificate(pair);

                // Store private key with its certificate chain
                KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(
                    rsaPrivateKey, certChain);
                keyStore.setEntry(KEY_ALIAS, pkEntry,
                    new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));

                // Save keystore
                try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
                    keyStore.store(fos, KEY_STORE_PASSWORD.toCharArray());
                }

                logger.info("Generated and stored new RSA keys in keystore");
            }
        } catch (Exception e) {
            logger.severe("Error handling RSA keys: " + e.getMessage());
            throw new RuntimeException("Failed to handle RSA keys", e);
        }
    }

    private X509Certificate[] createSelfSignedCertificate(KeyPair keyPair) throws Exception {
        // Create self-signed certificate
        X500Name dnName = new X500Name("CN=ResourceServer");
        BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis()));
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA")
            .build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter()
            .getCertificate(certHolder);

        return new X509Certificate[]{cert};
    }

    public String getServerRSAPublicKeyPEM() {
        try {
            byte[] publicKeyBytes = rsaPublicKey.getEncoded();
            return Base64.getEncoder().encodeToString(publicKeyBytes);
        } catch (Exception e) {
            logger.severe("Failed to get RSA public key: " + e.getMessage());
            throw new RuntimeException("Failed to get RSA public key", e);
        }
    }

    public PrivateKey getServerRSAPrivateKey() {
        return rsaPrivateKey;
    }

    public byte[] generateECDHKeyPair() {
        try {
            // Generate EC key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Store private key
            currentECDHPrivateKey = keyPair.getPrivate();

            // Get public key in raw uncompressed format
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
            ECPoint w = ecPublicKey.getW();
            byte[] x = w.getAffineX().toByteArray();
            byte[] y = w.getAffineY().toByteArray();

            // Ensure x and y are 32 bytes each by padding or trimming
            x = adjustByteArrayLength(x);
            y = adjustByteArrayLength(y);

            // Create uncompressed point format (0x04 || x || y)
            byte[] rawKey = new byte[65];
            rawKey[0] = 0x04;
            System.arraycopy(x, 0, rawKey, 1, 32);
            System.arraycopy(y, 0, rawKey, 33, 32);

            return rawKey;

        } catch (Exception e) {
            logger.severe("Failed to generate ECDH key pair: " + e.getMessage());
            throw new RuntimeException("Failed to generate ECDH key pair", e);
        }
    }

    private byte[] adjustByteArrayLength(byte[] input) {
        if (input.length == 32) {
            return input;
        }
        byte[] result = new byte[32];
        if (input.length > 32) {
            // Trim from the left (preserve least significant bytes)
            System.arraycopy(input, input.length - 32, result, 0, 32);
        } else {
            // Pad with zeros on the left
            System.arraycopy(input, 0, result, 32 - input.length, input.length);
        }
        return result;
    }
    

    public byte[] computeSharedSecret(byte[] clientPublicKeyRaw) {
        try {
            // Check if it's in uncompressed format (starts with 0x04)
            if (clientPublicKeyRaw[0] != 0x04 || clientPublicKeyRaw.length != 65) {
                throw new IllegalArgumentException("Invalid public key format");
            }

            // Extract x and y coordinates
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            System.arraycopy(clientPublicKeyRaw, 1, x, 0, 32);
            System.arraycopy(clientPublicKeyRaw, 33, y, 0, 32);

            // Create EC point
            ECParameterSpec params = ((ECPrivateKey) currentECDHPrivateKey).getParams();
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));

            // Create public key
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECPublicKeySpec keySpec = new ECPublicKeySpec(point, params);
            PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

            // Generate shared secret
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(currentECDHPrivateKey);
            keyAgreement.doPhase(clientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Hash the shared secret
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            // Get the AES key

            // byte[] derived = digest.digest(sharedSecret);
            aesKey = deriveKey(sharedSecret);
            logger.info("Within KeyService printing aesKey: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));
            
            return digest.digest(sharedSecret);

        } catch (Exception e) {
            logger.severe("Failed to compute shared secret: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to compute shared secret", e);
        }
    }
private static final int GCM_IV_LENGTH = 16;
private static final int GCM_TAG_LENGTH = 16 * 8; // 16 bytes * 8 = 128 bits

public Map<String, String> encrypt(String plaintext) {
    try {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        // Encode plaintext as UTF-8 bytes and encrypt
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Split ciphertext and auth tag
        int authTagOffset = ciphertext.length - (GCM_TAG_LENGTH / 8);
        byte[] encryptedData = new byte[authTagOffset];
        byte[] authTag = new byte[GCM_TAG_LENGTH / 8];
        System.arraycopy(ciphertext, 0, encryptedData, 0, authTagOffset);
        System.arraycopy(ciphertext, authTagOffset, authTag, 0, GCM_TAG_LENGTH / 8);

        // Encode components as Base64
        Map<String, String> result = new HashMap<>();
        result.put("encrypted", Base64.getEncoder().encodeToString(encryptedData));
        result.put("iv", Base64.getEncoder().encodeToString(iv));
        result.put("authTag", Base64.getEncoder().encodeToString(authTag));

        return result;
    } catch (Exception e) {
        logger.severe("Encryption failed: " + e.getMessage());
        throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
    }
}

public String decrypt(Map<String, String> encryptedData) {
    try {
        // Validate input
        if (!encryptedData.containsKey("encrypted") || 
            !encryptedData.containsKey("iv") || 
            !encryptedData.containsKey("authTag")) {
            throw new IllegalArgumentException("Missing required encryption fields");
        }

        // Decode from Base64
        byte[] iv = Base64.getDecoder().decode(encryptedData.get("iv"));
        byte[] ciphertext = Base64.getDecoder().decode(encryptedData.get("encrypted"));
        byte[] authTag = Base64.getDecoder().decode(encryptedData.get("authTag"));

        // Validate lengths
        if (iv.length != GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid IV length");
        }
        if (authTag.length != GCM_TAG_LENGTH / 8) {
            throw new IllegalArgumentException("Invalid auth tag length");
        }

        // Combine ciphertext and auth tag
        byte[] combined = new byte[ciphertext.length + authTag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(authTag, 0, combined, ciphertext.length, authTag.length);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        // Decrypt and convert to string
        byte[] plaintext = cipher.doFinal(combined);
        return new String(plaintext, StandardCharsets.UTF_8);
    } catch (Exception e) {
        logger.severe("Decryption failed: " + e.getMessage());
        throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
    }
}
    // private static SecretKey deriveKey(byte[] sharedSecret){ 
    //     byte [] salt = new byte[0];
    //     byte [] info = new byte[0];
    //     int keySize = 32;
    //     HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new org.bouncycastle.crypto.digests.SHA256Digest()); 
    //     hkdf.init(new HKDFParameters(sharedSecret, salt, info)); 
    //     byte[] keyBytes = new byte[keySize]; hkdf.generateBytes(keyBytes, 0, keyBytes.length); 
    //     return new SecretKeySpec(keyBytes, "AES"); 

    // }
    public static SecretKey deriveKey(byte[] sharedSecret) {
        // Create empty salt and info buffers to match Node.js Buffer.alloc(0)
        byte[] salt = new byte[0];
        byte[] info = new byte[0];
        
        // Output key size (32 bytes for AES-256)
        int keySize = 32;
        
        try {
            // Initialize HKDF with SHA-256
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            
            // Initialize with parameters matching Node.js implementation
            HKDFParameters params = new HKDFParameters(sharedSecret, salt, info);
            hkdf.init(params);
            
            // Generate the key bytes
            byte[] keyBytes = new byte[keySize];
            hkdf.generateBytes(keyBytes, 0, keySize);
            
            // Create SecretKey for AES
            return new SecretKeySpec(keyBytes, "AES");
            
        } catch (Exception e) {
            throw new RuntimeException("Error deriving key: " + e.getMessage(), e);
        }
    }
    

    private static SecretKey testDerive(byte[] derived){
        return new SecretKeySpec(derived, "AES");
    }

    public String calculateFingerprint(String publicKeyPEM) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Base64.getDecoder().decode(publicKeyPEM));

            StringBuilder fingerprint = new StringBuilder();
            for (byte b : hash) {
                if (fingerprint.length() > 0) fingerprint.append(':');
                fingerprint.append(String.format("%02X", b & 0xff));
            }
            return fingerprint.toString();
        } catch (Exception e) {
            logger.severe("Failed to calculate fingerprint: " + e.getMessage());
            throw new RuntimeException("Failed to calculate fingerprint", e);
        }
    }
}