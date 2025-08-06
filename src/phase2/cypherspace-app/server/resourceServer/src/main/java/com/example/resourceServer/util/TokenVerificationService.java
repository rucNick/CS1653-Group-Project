package com.example.resourceServer.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

@Service
public class TokenVerificationService {
    private PublicKey authServerPublicKey;
    private static final String AUTH_PUBLIC_KEY_FILE = "auth_public_key.pem";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final Logger logger = Logger.getLogger(TokenVerificationService.class.getName());
    private String resourceFingerPrint = "";

    // Inner class for verification result
    public static class VerificationResult {
        private final boolean isValid;
        private final Map<String, Object> verifiedData;

        public VerificationResult(boolean isValid, Map<String, Object> verifiedData) {
            this.isValid = isValid;
            this.verifiedData = verifiedData;
        }

        public boolean isValid() {
            return isValid;
        }

        public Map<String, Object> getVerifiedData() {
            return verifiedData;
        }
    }

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        loadPublicKeyFromFile();
    }

    private void loadPublicKeyFromFile() {
        try {
            // Load the file from the project root directory
            File file = new File(AUTH_PUBLIC_KEY_FILE);
            if (!file.exists()) {
                throw new FileNotFoundException("Public key file not found: " + AUTH_PUBLIC_KEY_FILE);
            }

            try (PemReader pemReader = new PemReader(new FileReader(file))) {
                PemObject pemObject = pemReader.readPemObject();
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pemObject.getContent());
                KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
                authServerPublicKey = keyFactory.generatePublic(publicKeySpec);
                logger.info("Authentication server public key loaded successfully from project root.");
            }
        } catch (Exception e) {
            logger.severe("Failed to load public key: " + e.getMessage());
            throw new RuntimeException("Failed to load authentication server public key", e);
        }
    }


    public VerificationResult verifyAuthentication(Map<String, Object> authData) {
        try {
            logger.info("Verifying auth data");
            String signature = (String) authData.get("signature");
            if (signature == null) {
                logger.info("No signature found in auth data");
                return new VerificationResult(false, null);
            }

            Map<String, Object> dataToVerify = new HashMap<>(authData);
            dataToVerify.remove("signature");

            String jsonToVerify = objectMapper.writeValueAsString(dataToVerify);
            logger.info("Data to verify: " + jsonToVerify);

            Signature sig = Signature.getInstance("SHA256withRSA", "BC");
            sig.initVerify(authServerPublicKey);
            sig.update(jsonToVerify.getBytes());

            boolean isValid = sig.verify(Base64.getDecoder().decode(signature));
            logger.info("Signature verification result: " + isValid);

            /*-----------T7 here as well for getting posts------------------*/
            String requestedFingerPrint = (String)authData.get("fingerPrint");
            if(!requestedFingerPrint.contentEquals(resourceFingerPrint)){
                logger.info("Fingerprints do not match");
                return new VerificationResult(false, null);
            }
            /*----------END OF T7-------------*/

            return new VerificationResult(isValid, isValid ? dataToVerify : null);
        } catch (Exception e) {
            logger.severe("Error verifying authentication: " + e.getMessage());
            return new VerificationResult(false, null);
        }
    }

    public VerificationResult validateAddPostRequest(Map<String, Object> request) {
        try {
            Map<String, Object> trueParams = (Map<String, Object>) request.get("trueParams");
            if (trueParams == null) {
                logger.warning("No trueParams found in request");
                return new VerificationResult(false, null);
            }

            VerificationResult authResult = verifyAuthentication(trueParams);
            if (!authResult.isValid()) {
                return authResult;
            }

            Map<String, Object> verifiedData = authResult.getVerifiedData();

            // Verify data matches
            boolean userIdMatch = String.valueOf(request.get("userID"))
                    .equals(String.valueOf(verifiedData.get("userID")));
            boolean isVIPMatch = request.get("isVIP")
                    .equals(verifiedData.get("isVIP"));
            boolean groupMatch = verifyGroups(request.get("groupName"), verifiedData.get("groups"));

            if (!userIdMatch || !isVIPMatch || !groupMatch) {
                logger.warning("Request data doesn't match verified data");
                return new VerificationResult(false, null);
            }

            /*-----------T7 here as well for getting posts------------------*/
            String requestedFingerPrint = (String)trueParams.get("fingerPrint");
            if(!requestedFingerPrint.contentEquals(resourceFingerPrint)){
                logger.info("Fingerprints do not match");
                return new VerificationResult(false, null);
            }
            /*----------END OF T7-------------*/


            return authResult;
        } catch (Exception e) {
            logger.severe("Error validating add post request: " + e.getMessage());
            return new VerificationResult(false, null);
        }
    }

    public VerificationResult validateDeletePostRequest(Map<String, Object> request) {
        try {
            Map<String, Object> trueParams = (Map<String, Object>) request.get("trueParams");
            if (trueParams == null) {
                logger.warning("No trueParams found in delete request");
                return new VerificationResult(false, null);
            }

            VerificationResult authResult = verifyAuthentication(trueParams);
            if (!authResult.isValid()) {
                return authResult;
            }

            Map<String, Object> verifiedData = authResult.getVerifiedData();

            // Verify data matches
            boolean userIdMatch = String.valueOf(request.get("userID"))
                    .equals(String.valueOf(verifiedData.get("userID")));
            boolean isAdminMatch = String.valueOf(request.get("isAdmin"))
                    .equals(String.valueOf(verifiedData.get("isAdmin")));

            if (!userIdMatch || !isAdminMatch) {
                logger.warning("Request data doesn't match verified data");
                return new VerificationResult(false, null);
            }

            /*-----------T7 here as well for getting posts------------------*/
            String requestedFingerPrint = (String)trueParams.get("fingerPrint");
            if(!requestedFingerPrint.contentEquals(resourceFingerPrint)){
                logger.info("Fingerprints do not match");
                return new VerificationResult(false, null);
            }
            /*----------END OF T7-------------*/

            return authResult;
        } catch (Exception e) {
            logger.severe("Error validating delete request: " + e.getMessage());
            return new VerificationResult(false, null);
        }
    }

    private boolean verifyGroups(Object requestGroup, Object verifiedGroups) {
        try {
            if (verifiedGroups instanceof List) {
                List<String> verifiedGroupsList = (List<String>) verifiedGroups;
                if (requestGroup instanceof String) {
                    return verifiedGroupsList.contains(requestGroup);
                } else if (requestGroup instanceof List) {
                    List<String> requestGroups = (List<String>) requestGroup;
                    return verifiedGroupsList.containsAll(requestGroups);
                }
            }
            return false;
        } catch (Exception e) {
            logger.severe("Error verifying groups: " + e.getMessage());
            return false;
        }
    }

    public void setFingerPrint(String fingerPrint){
        resourceFingerPrint = fingerPrint;
    }
}