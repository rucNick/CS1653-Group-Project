package com.example.resourceServer;

import com.example.resourceServer.entity.Post;
import com.example.resourceServer.entity.EncryptedObject;
import com.example.resourceServer.repository.PostRepository;
import com.example.resourceServer.service.KeyService;
import com.example.resourceServer.service.RequestSequenceService;
import com.example.resourceServer.util.TokenVerificationService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.core.JsonProcessingException;

import javax.annotation.PostConstruct;
import java.nio.ByteBuffer;
import java.security.Security;
import java.security.Signature;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import com.fasterxml.jackson.databind.ObjectMapper;
@RestController
public class MyController {

    @Autowired
    private PostRepository postRepository;

    @Autowired
    private KeyService keyService;

    @Autowired
    private TokenVerificationService tokenVerificationService;

    @Autowired
    private RequestSequenceService requestSequenceService;

    private final ExecutorService executorService;

    private static final Logger logger = Logger.getLogger(MyController.class.getName());

    private String fingerprint = "";

    public MyController(ExecutorService executorService){
        this.executorService = executorService;
    }

    /*--------Verify Server Methods-----------*/

    @PostConstruct
    public void init() {
        // Register Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
        String rsaPublicKey = keyService.getServerRSAPublicKeyPEM();
        fingerprint = keyService.calculateFingerprint(rsaPublicKey);
        tokenVerificationService.setFingerPrint(fingerprint);
    }

    @GetMapping("/server-identity")
    public ResponseEntity<Map<String, String>> getServerIdentity() {
        try {
            String rsaPublicKey = keyService.getServerRSAPublicKeyPEM();
            // String fingerprint = keyService.calculateFingerprint(rsaPublicKey);
            // tokenVerificationService.setFingerPrint(fingerprint);

//            if(resourceFingerPrint.length() == 0){
//                resourceFingerPrint = fingerprint;
//            }
            // String fingerprint = keyService.calculateFingerprint(rsaPublicKey);
            // tokenVerificationService.setFingerPrint(fingerprint);

            Map<String, String> response = new HashMap<>();
            response.put("publicKey", rsaPublicKey);
            response.put("fingerprint", fingerprint);

            logger.info("Server identity provided successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.severe("Error providing server identity: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/verify-identity")
    public ResponseEntity<Map<String, String>> verifyIdentity(@RequestBody Map<String, String> request) {
        try {
            // Extract challenge and client's ECDH public key
            byte[] challenge = Base64.getDecoder().decode(request.get("challenge"));
            byte[] clientECDHPublic = Base64.getDecoder().decode(request.get("ecdhPublicKey"));

            // Generate server's ECDH key pair
            byte[] serverECDHPublic = keyService.generateECDHKeyPair();

            // Compute shared secret (optional, can be done later)
            byte[] sharedSecret = keyService.computeSharedSecret(clientECDHPublic);
          
            // Concatenate data to sign: challenge || clientECDHPublic || serverECDHPublic
            byte[] dataToSign = ByteBuffer.allocate(challenge.length +
                            clientECDHPublic.length + serverECDHPublic.length)
                    .put(challenge)
                    .put(clientECDHPublic)
                    .put(serverECDHPublic)
                    .array();

            // Sign with RSA private key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyService.getServerRSAPrivateKey());
            signature.update(dataToSign);
            byte[] signatureBytes = signature.sign();

            // Create response
            Map<String, String> response = new HashMap<>();
            response.put("ecdhServerPublic", Base64.getEncoder().encodeToString(serverECDHPublic));
            response.put("signature", Base64.getEncoder().encodeToString(signatureBytes));

            logger.info("Server identity verified successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.severe("Error during server verification: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    /*---------End of verify server methods------*/

    @PostMapping("/addPost")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> addPost(@RequestBody Map<String, String> encryptedData) {
        return CompletableFuture.supplyAsync(() -> {
            logger.info("HELLO IS THIS EVEN BEIGN CALLED?");
            try {

                logger.info("Validating input in addPost");
                // Validate input
                if (!encryptedData.containsKey("encrypted") || 
                    !encryptedData.containsKey("iv") || 
                    !encryptedData.containsKey("authTag")) {
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid encryption format"));
                }

                logger.info("decrypting the encryptedData");
                // Decrypt the request
                String decrypted = keyService.decrypt(encryptedData);
                Map<String, Object> rDetails = new ObjectMapper().readValue(
                    decrypted, 
                    new TypeReference<Map<String, Object>>() {}
                );

                logger.info("Verifying the token and metadata integritty");
                // Step 1: Verify token and metadata integrity
                TokenVerificationService.VerificationResult verificationResult =
                        tokenVerificationService.validateAddPostRequest(rDetails);

                logger.info("Checking if the result is valid");
                if (!verificationResult.isValid()) {
                    logger.warning("Token validation or data integrity check failed");
                    return createErrorResponse("Invalid token or tampered data", HttpStatus.UNAUTHORIZED);
                }

                logger.info("Get the verified data");
                // Step 2: Get verified data
                Map<String, Object> verifiedData = verificationResult.getVerifiedData();

                logger.info("Extract the content from requests");
                // Step 3: Extract content and title from request
                Map<String, String> requestDetails = convertToStringMap(rDetails);
                String content = requestDetails.get("content");
                logger.info("Content:" + content);
                String title = requestDetails.get("title");
                logger.info("Title:" + title);
                String user = requestDetails.get("user"); // From request as auth server doesn't provide username

                logger.info("Now step4");
                // Step 4: Use verified data for sensitive fields
                boolean isVIP = (boolean) verifiedData.get("isVIP");
                List<String> groups = (List<String>) verifiedData.get("groups");
                String groupName = groups.get(0); // Use first group
                Long userID = Long.valueOf(verifiedData.get("userID").toString());
                logger.info("userID + " + userID);
                logger.info("version + " + requestDetails.get("version"));
                Long version = Long.valueOf(requestDetails.get("version").toString());
                logger.info("version + " + version);

                /*---------------------T5-------------------------*/

                // CHECKING SEQUENCE NUMBER HEREEE FOR T5
                logger.info("Checking the sequence number");
                int expectedSequence = requestSequenceService.getCurrentSequence(userID);
                int receivedSequence = Integer.parseInt(String.valueOf(rDetails.get("sequence")));
                if(expectedSequence != receivedSequence){
                    logger.warning("Sequence does not match");
                    return createErrorResponse("Invalid sequence number", HttpStatus.UNAUTHORIZED);
                } else{ // Else the sequence is valid so update it to get ready to receive another
                    requestSequenceService.getAndIncrement(userID);
                }

                /*-----------------END OF T5----------------*/

                logger.info("now step 5");
                // Step 5: Validate required fields
                if (content == null || title == null || user == null) {
                    return createErrorResponse("Content, title, and user are required", HttpStatus.BAD_REQUEST);
                }

                logger.info("step 6");
                // Step 6: Create and save post

                ObjectMapper mapper = new ObjectMapper();
            
                // Extract the encrypted title and content objects
                // EncryptedObject titleObj = mapper.readValue(
                //     mapper.writeValueAsString(rDetails.get("title")), 
                //     EncryptedObject.class
                // );
                
                // EncryptedObject contentObj = mapper.readValue(
                //     mapper.writeValueAsString(rDetails.get("content")), 
                //     EncryptedObject.class
                // );

                // Create new post with serialized encrypted objects
                // Post newPost = new Post();
                // newPost.setTitleObject(titleObj);
                // newPost.setContentObject(contentObj);
                // newPost.setUser(requestDetails.get("user"));
                // newPost.setVIP(Boolean.parseBoolean(requestDetails.get("isVIP")));
                // newPost.setGroup(requestDetails.get("groupName"));
                // newPost.setUserId(Long.parseLong(requestDetails.get("userID")));
                // newPost.setVersion(Long.parseLong(requestDetails.get("version")));

                Post newPost = new Post(content,user,isVIP,title,groupName,userID,version);

                // Post newPost = new Post(content, user, isVIP, title, groupName, userID, version);
                postRepository.save(newPost);

                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("message", "Post added successfully");
                logger.info("New post added by user=" + user + ", isVIP=" + isVIP);

                String responseJson = new ObjectMapper().writeValueAsString(response);

                Map<String, String> encryptedResponse = keyService.encrypt(responseJson);

                logger.info("encryptedResponse in addPost: " + encryptedResponse);

                return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("encryptedData",encryptedResponse));

            } catch (Exception e) {
                logger.severe("Error adding posts: " + e.getMessage());
                try {
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Internal server error"))
                    );
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("encryptedData", errorResponse));
                } catch (Exception encryptError) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Encryption failed"));
                }
            }
            
        }, executorService);
    }

    @PostMapping("/getAllPosts")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> getAllPosts(@RequestBody Map<String, String> encryptedData) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Validate input
                if (!encryptedData.containsKey("encrypted") || 
                    !encryptedData.containsKey("iv") || 
                    !encryptedData.containsKey("authTag")) {
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid encryption format"));
                }

                // Decrypt the request
                String decrypted = keyService.decrypt(encryptedData);
                Map<String, Object> requestDetails = new ObjectMapper().readValue(
                    decrypted, 
                    new TypeReference<Map<String, Object>>() {}
                );

                // Extract and verify trueParams
                Map<String, Object> trueParams = (Map<String, Object>) requestDetails.get("trueParams");
                if (trueParams == null) {
                    logger.warning("No trueParams found in getAllPosts request");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Unauthorized"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("encryptedData", errorResponse));
                }

                TokenVerificationService.VerificationResult verificationResult =
                        tokenVerificationService.verifyAuthentication(trueParams);
                if (!verificationResult.isValid()) {
                    logger.warning("Authentication failed for getAllPosts");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Authentication failed"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("encryptedData", errorResponse));
                }

                // Use verified data
                Map<String, Object> verifiedData = verificationResult.getVerifiedData();
                boolean isVIP = (boolean) verifiedData.get("isVIP");
                List<String> groups = (List<String>) verifiedData.get("groups");

                // Get posts for this user's groups
                List<Post> allPosts = postRepository.findByGroupNameIn(groups);

                // Filter based on VIP status
                List<Post> filteredPosts;
                if (!isVIP) {
                    filteredPosts = allPosts.stream()
                            .filter(post -> !post.isVIP())
                            .collect(Collectors.toList());
                } else {
                    filteredPosts = allPosts;
                }

                // // Convert posts to a format where title and content are objects
                // List<Map<String, Object>> postsWithObjects = filteredPosts.stream()
                // .map(post -> {
                //     Map<String, Object> postMap = new HashMap<>();
                //     postMap.put("postID", post.getPostID());
                //     postMap.put("title", post.getTitleObject());
                //     postMap.put("content", post.getContentObject());
                //     postMap.put("user", post.getUser());
                //     postMap.put("isVIP", post.isVIP());
                //     postMap.put("groupName", post.getGroupName());
                //     postMap.put("userID", post.getUserId());
                //     postMap.put("version", post.getVersion());
                //     return postMap;
                // })
                // .collect(Collectors.toList());

                // Encrypt the filtered posts
                Map<String, String> encryptedResponse = keyService.encrypt(
                    new ObjectMapper().writeValueAsString(filteredPosts)
                );

                return ResponseEntity.ok(Map.of("encryptedData", encryptedResponse));

            } catch (Exception e) {
                logger.severe("Error retrieving posts: " + e.getMessage());
                try {
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Internal server error"))
                    );
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("encryptedData", errorResponse));
                } catch (Exception encryptError) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Encryption failed"));
                }
            }
        }, executorService);
    }

    @PostMapping("/test")
    public CompletableFuture<ResponseEntity<String>> getNormalPosts(@RequestBody Map<String, Object> rDetails) {
        return CompletableFuture.supplyAsync(() -> {

            // Object titleObj = requestDetails.get("title");
            Map<String, String> requestDetails = convertToStringMap(rDetails);
            // String testHolder = titleObj != null ? titleObj.toString() : null;
            String testHolder = requestDetails.get("title");

            logger.info("Printing the title string:" + testHolder);

            // List<Post> normalPosts = postRepository.findByIsVIPFalse();
            // if (normalPosts.isEmpty()) {
            //     return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
            // }
            // return ResponseEntity.ok(normalPosts);
            return ResponseEntity.ok("WORKS");
        }, executorService);
    }

    @GetMapping("/getGuestPosts")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> getGuestPosts() {
        return CompletableFuture.supplyAsync(() -> {

            try{

                // Find posts that are both non-VIP and in the guest group
                List<Post> guestPosts = postRepository.findByIsVIPFalseAndGroupNameIgnoreCase("guest");

                if (guestPosts.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
                }

                System.out.println("\nprinting guestPosts List: ");
                for(Post p : guestPosts){
                    System.out.println("Printing the title of guestPost: " + p.getTitle());
                }
                String gpString = new ObjectMapper().writeValueAsString(guestPosts);
                System.out.println("\nnow printing the list as a string before encrypting: " + gpString);

                // Encrypt the guest posts
                Map<String, String> encryptedResponse = keyService.encrypt(
                    new ObjectMapper().writeValueAsString(guestPosts)
                );

                System.out.println("\nPrinting the encryptedResponse: " + new ObjectMapper().writeValueAsString(encryptedResponse));

                return ResponseEntity.ok(Map.of("encryptedData", encryptedResponse));

            }catch (Exception e){
                logger.severe("Error retrieving posts: " + e.getMessage());
                try {
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Internal server error"))
                    );
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("encryptedData", errorResponse));
                } catch (Exception encryptError) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Encryption failed"));
                }
            }
        }, executorService);
    }


    @PostMapping("/getGroupPosts")
    public CompletableFuture<ResponseEntity<Map<String,Object>>> getGroupPosts(@RequestBody Map<String, String> encryptedData) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Validate input
                if (!encryptedData.containsKey("encrypted") || 
                    !encryptedData.containsKey("iv") || 
                    !encryptedData.containsKey("authTag")) {
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid encryption format"));
                }

                // Decrypt the request
                String decrypted = keyService.decrypt(encryptedData);
                Map<String, Object> requestDetails = new ObjectMapper().readValue(
                    decrypted, 
                    new TypeReference<Map<String, Object>>() {}
                );

                // Extract and verify trueParams
                Map<String, Object> trueParams = (Map<String, Object>) requestDetails.get("trueParams");
                if (trueParams == null) {
                    logger.warning("No trueParams found in getGroupPosts request");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Unauthorized"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("encryptedData", errorResponse));
                }

                TokenVerificationService.VerificationResult verificationResult =
                        tokenVerificationService.verifyAuthentication(trueParams);
                if (!verificationResult.isValid()) {
                    logger.warning("Authentication failed for getGroupPosts");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Authentication failed"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("encryptedData", errorResponse));
                }

                // Use verified data
                Map<String, Object> verifiedData = verificationResult.getVerifiedData();
                boolean isVIP = (boolean) verifiedData.get("isVIP");
                List<String> groups = (List<String>) verifiedData.get("groups");

                // Get posts for this user's groups
                List<Post> allPosts = postRepository.findByGroupNameIn(groups);

                // Filter based on VIP status
                List<Post> filteredPosts;
                if (!isVIP) {
                    filteredPosts = allPosts.stream()
                            .filter(post -> !post.isVIP())
                            .collect(Collectors.toList());
                } else {
                    filteredPosts = allPosts;
                }

                // Encrypt the filtered posts
                Map<String, String> encryptedResponse = keyService.encrypt(
                    new ObjectMapper().writeValueAsString(filteredPosts)
                );

                return ResponseEntity.ok(Map.of("encryptedData", encryptedResponse));


            } catch (Exception e) {
                logger.severe("Error processing getGroupPosts request: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
        }, executorService);
    }

    @Transactional
    @DeleteMapping("/deleteUserPosts")
    public CompletableFuture<ResponseEntity<Map<String,Object>>> deleteUserPosts(@RequestBody Map<String, String> details) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Validate input
                if (!details.containsKey("encrypted") || 
                    !details.containsKey("iv") || 
                    !details.containsKey("authTag")) {
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid encryption format"));
                }

                // Decrypt the request
                String decrypted = keyService.decrypt(details);
                Map<String, Object> requestDetails = new ObjectMapper().readValue(
                    decrypted, 
                    new TypeReference<Map<String, Object>>() {}
                );

                Map<String, Object> trueParams = (Map<String, Object>) requestDetails.get("trueParams");
                if (trueParams == null) {
                    logger.warning("No trueParams found in deleteUserPosts request");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Authentication required"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("error",errorResponse));
                }

                // Verify the authentication token
                TokenVerificationService.VerificationResult verificationResult =
                        tokenVerificationService.verifyAuthentication(trueParams);

                if (!verificationResult.isValid()) {
                    logger.warning("Authentication failed for deleteUserPosts");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Authentication failed"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("encryptedData",errorResponse));
                }

                // Get verified data
                Map<String, Object> verifiedData = verificationResult.getVerifiedData();
                boolean isAdmin = Boolean.parseBoolean(String.valueOf(verifiedData.get("isAdmin")));

                if (!isAdmin) {
                    logger.warning("Non-admin user attempted to delete user posts");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Access Denied: Admin privileges required"))
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("error", errorResponse));
                }

                // Get target userID from request
                Long targetUserID;
                try {
                    targetUserID = Long.parseLong(String.valueOf(requestDetails.get("userID")));
                } catch (NumberFormatException e) {
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Bad Request"))
                    );
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of("encryptedData",errorResponse));
                }

                // Delete posts
                if (postRepository.existsByUserID(targetUserID)) {
                    postRepository.deleteByUserID(targetUserID);
                    logger.info("All posts deleted for userID: " + targetUserID);

                    String successMessage = "All posts deleted for userID: " + targetUserID;
                    // Encrypt the message
                    Map<String, String> successResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("data", successMessage))
                    );

                    return ResponseEntity.ok(Map.of("encryptedData", successResponse));

                } else {
                    
                    Map<String, String> noPostsResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "No Posts found for specified user"))
                    );

                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("encryptedData", noPostsResponse));
                }

            } catch (JsonProcessingException e) { 
                logger.severe("Error processing addPost request: " + e.getMessage()); 
                Map<String, Object> errorResponse = new HashMap<>(); 
                errorResponse.put("error", "Error processing request"); 
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse); 
            } catch (Exception e) {
                logger.severe("Error deleteUserPosts: " + e.getMessage());
                try {
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Internal server error"))
                    );
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("encryptedData", errorResponse));
                } catch (Exception encryptError) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("error", "Encryption failed"));
                }
            }
        }, executorService);
    }

    @DeleteMapping("/deletePost")
    public CompletableFuture<ResponseEntity<Map<String,Object>>> deletePost(@RequestBody Map<String, String> rDetails) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                    // Validate input
                if (!rDetails.containsKey("encrypted") || 
                    !rDetails.containsKey("iv") || 
                    !rDetails.containsKey("authTag")) {
                    return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid encryption format"));
                }

                // Decrypt the request
                String decrypted = keyService.decrypt(rDetails);
                Map<String, Object> requestDetails = new ObjectMapper().readValue(
                    decrypted, 
                    new TypeReference<Map<String, Object>>() {}
                );

                TokenVerificationService.VerificationResult verificationResult =
                        tokenVerificationService.validateDeletePostRequest(requestDetails);

                if (!verificationResult.isValid()) {
                    logger.warning("Token validation failed for delete request");
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Invalid Authentication"))
                    );
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("error", errorResponse));
                }

                Map<String, Object> verifiedData = verificationResult.getVerifiedData();
                Long postID = Long.parseLong(String.valueOf(requestDetails.get("postID")));
                Long userID = Long.parseLong(String.valueOf(verifiedData.get("userID")));
                boolean isAdmin = Boolean.parseBoolean(String.valueOf(verifiedData.get("isAdmin")));

                Optional<Post> post = postRepository.findById(postID);
                if (post.isEmpty()) { // No posts found
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "No posts found"))
                    );
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("error",errorResponse));
                }

                if (isAdmin || post.get().getUserId().equals(userID)) { // Post deleted by admin or the user
                    postRepository.delete(post.get());
                    String message = isAdmin ? "Post deleted by admin successfully" : "Post deleted successfully";
                    logger.info(message + " - Post: " + postID + ", User: " + userID);
                    Map<String, String> successResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("success", "Post deleted successfuly"))
                    );
                    
                    return ResponseEntity.ok(Map.of("encryptedData",successResponse));
                } else { // Not authorized to delete
                    logger.warning("Unauthorized delete attempt - Post: " + postID + ", User: " + userID);
                    Map<String, String> errorResponse = keyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("error", "Invalid Access"))
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("error",errorResponse));
                }

            } catch (JsonProcessingException e) { 
                logger.severe("Error processing addPost request: " + e.getMessage()); 
                Map<String, Object> errorResponse = new HashMap<>(); 
                errorResponse.put("error", "Error processing request"); 
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse); 
            } catch (NumberFormatException e) {
                logger.warning("Invalid ID format in delete request");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "Imvalid ID format in delete request");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(errorResponse);
            } catch (Exception e) {
                logger.severe("Error processing delete request: " + e.getMessage());
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "Error processing delete request");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
            }
        }, executorService);
    }



    /*--------Private Helper Methods---------*/

    private ResponseEntity<Map<String, Object>> createErrorResponse(String message, HttpStatus status) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", false);
        response.put("message", message);
        return ResponseEntity.status(status).body(response);
    }

    private static Map<String, String> convertToStringMap(Map<String, Object> originalMap) {
        Map<String, String> newMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : originalMap.entrySet()) {
            if (entry.getValue() != null) {
                if (entry.getValue() instanceof List) {
                    List<?> list = (List<?>) entry.getValue();
                    if (!list.isEmpty()) {
                        newMap.put(entry.getKey(), list.get(0).toString());
                    }
                } else {
                    newMap.put(entry.getKey(), entry.getValue().toString());
                }
            } else {
                newMap.put(entry.getKey(), null);
            }
        }
        return newMap;
    }
}