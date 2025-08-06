package com.example.spring.controller;

import com.example.spring.entity.Group;
import com.example.spring.entity.GroupKey;
import com.example.spring.entity.User;
import com.example.spring.entity.VipCode;
import com.example.spring.repository.GroupKeyRepository;
import com.example.spring.repository.GroupRepository;
import com.example.spring.repository.UserRepository;
import com.example.spring.repository.VipCodeRepository;
import com.example.spring.service.DHKeyService;
import com.example.spring.service.GroupKeyService;
import com.example.spring.service.PasswordService;
import com.example.spring.service.TokenService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    static final String server_fp="6E:67:48:E0:52:5A:70:E9:B9:68:88:20:C1:A8:F6:47:B8:44:4A:08:5D:51:D5:49:BC:F7:60:1F:4A:44:94:DF";
    @Autowired
    private GroupKeyService groupKeyService;

    // Injects the UserRepository to interact with User data in the database
    @Autowired
    private UserRepository userRepository;

    // Injects the VipCodeRepository to interact with VIP codes in the database
    @Autowired
    private VipCodeRepository vipCodeRepository;

    @Autowired
    private GroupKeyRepository groupKeyRepository;

    @Autowired
    private GroupRepository groupRepository;

    private final ExecutorService executorService;

    // Inject the ExecutorService from the ThreadPoolConfig
    public AuthController(ExecutorService executorService) {
        this.executorService = executorService;
    }

    //Inject the password-service that handle the password hashing
    @Autowired
    private PasswordService passwordService;

    //Token Service for the 2048 RSA
    @Autowired
    private TokenService tokenService;

    @Autowired
    private DHKeyService diffieHellmanKeyService;

    private static final Logger logger = Logger.getLogger(AuthController.class.getName());

//-----------------------------------------RSA Signature Methods----------------------------------------------------------------------------
    // Utility methods for response signing
    private Map<String, Object> signResponse(Map<String, Object> response) {
        if (response != null) {
            String signature = tokenService.signToken(response);
            response.put("signature", signature);
        }
        return response;
    }

    private ResponseEntity<Map<String, Object>> createSignedResponse(String status, String message, HttpStatus httpStatus) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        return ResponseEntity.status(httpStatus).body(signResponse(response));
    }

    private ResponseEntity<Map<String, Object>> createSignedResponse(String status, String message, Object data, HttpStatus httpStatus) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", status);
        response.put("message", message);
        if (data != null) {
            response.put("data", data);
        }
        return ResponseEntity.status(httpStatus).body(signResponse(response));
    }

    //-------------------------------------------DH EndPoints-------------------------------------------------------------------------

    @GetMapping("/test-key")
    public ResponseEntity<Map<String, Object>> testKey(HttpSession session) {
        SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
        System.out.println("Test request received. Session ID: " + session.getId());
        System.out.println("Has shared key: " + (sharedKey != null));

        if (sharedKey == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "error",
                            "message", "No encryption key established"));
        }

        return ResponseEntity.ok(Map.of("status", "success",
                "message", "Encryption key verified"));
    }

    @PostMapping("/initiate-key-exchange")
    public ResponseEntity<Map<String, String>> initiateKeyExchange() {
        try {
            String serverPublicKey = diffieHellmanKeyService.getServerPublicKey();
            return ResponseEntity.ok(Map.of(
                "serverPublicKey", serverPublicKey,
                "status", "success"
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Key exchange failed"));
        }
    }

    @PostMapping("/complete-key-exchange")
    public ResponseEntity<Map<String, Object>> completeKeyExchange(
            @RequestBody Map<String, String> request,
            HttpSession session) {
        try {
            String clientPublicKeyBase64 = request.get("clientPublicKey");
            if (clientPublicKeyBase64 == null) {
                return ResponseEntity.badRequest()
                        .body(Map.of(
                                "status", "error",
                                "message", "No public key provided"
                        ));
            }

            // Generate shared key
            SecretKey sharedKey = diffieHellmanKeyService.generateSharedSecret(clientPublicKeyBase64);

            // Store in session with logging
            session.setAttribute("sharedKey", sharedKey);
            System.out.println("Stored shared key in session: " + session.getId());
            System.out.println("Key algorithm: " + sharedKey.getAlgorithm());
            System.out.println("Key length: " + sharedKey.getEncoded().length);
            System.out.println("Key Raw Data: " + Base64.getEncoder().encodeToString(sharedKey.getEncoded()));
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("keyAlgorithm", sharedKey.getAlgorithm());
            response.put("keyLength", sharedKey.getEncoded().length);
            response.put("sessionId", session.getId());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.err.println("Key exchange failed: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "status", "error",
                            "message", "Key exchange failed: " + e.getMessage(),
                            "error", e.getClass().getSimpleName()
                    ));
        }
    }

    //---------------------------------------------main endpoints----------------------------------------------------------------------------------
    @PostMapping("/initializeGroupKeys")
    public ResponseEntity<Map<String, Object>> initializeGroupKeys(@RequestBody Map<String, Object> request) {
        Boolean isAdmin = (Boolean) request.get("isAdmin");
        if (isAdmin == null || !isAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "status", "error",
                            "message", "Not authorized"
                    ));
        }

        List<Group> groups = groupRepository.findAllWithUsers();
        int initializedCount = 0;
        List<String> initializedGroups = new ArrayList<>();

        for (Group group : groups) {
            // Check key count using groupKeyRepository
            if (groupKeyRepository.getKeyCountForGroup(group) == 0) {
                groupKeyService.initializeGroupKey(group);
                logger.info("Initialized key for group: " + group.getGroupName());
                initializedGroups.add(group.getGroupName());
                initializedCount++;
            }
        }

        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Group keys initialized successfully",
                "initializedCount", initializedCount,
                "initializedGroups", initializedGroups
        ));
    }

    /**
     * Verifies a user's credentials asynchronously.
     *
     * @param encryptedData the Encrypted user information for login
     * @return the verification result and encrypted data.
     */
    @PostMapping("/verify")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> verifyUser(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                System.out.println("Verify request received. Session ID: " + session.getId());
                System.out.println("Has shared key: " + (session.getAttribute("sharedKey") != null));

                // Retrieve the shared key from the session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.out.println("No shared key found in session");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error",
                                    "message", "No encryption key established"));
                }

                System.out.println("Encrypted data received: " + encryptedData);

                // Decrypt and verify
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                HashMap<String, String> credentials = new ObjectMapper()
                        .readValue(decryptedData, HashMap.class);

                System.out.println("Credentials decrypted for user: " + credentials.get("username"));

                // Verify user credentials
                HashMap<String, Object> verificationResult = verify_User(credentials);
                System.out.println("Verification result: " + verificationResult);

                // Encrypt the response
                Map<String, String> encryptedResponse = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(verificationResult),
                        sharedKey
                );

                return ResponseEntity.ok(Map.of(
                        "encryptedData", encryptedResponse,
                        "status", "success"
                ));

            } catch (Exception e) {
                System.err.println("Error in verify endpoint: " + e.getMessage());
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error",
                                "message", "Verification failed: " + e.getMessage()));
            }
        }, executorService);
    }
    /**
     * Registers a new user.
     *
     * @param encryptedData
     * @return A ResponseEntity containing a success message and the user's registration status.
     */
    @PostMapping("/register")
    @Transactional
    public CompletableFuture<ResponseEntity<Map<String, Object>>> registerUserAsync(
            @RequestBody Map<String, String> encryptedData, HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Retrieve the shared key from the session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("[Auth Server] No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                // Decrypt the incoming data
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, String> userDetails = new ObjectMapper().readValue(decryptedData, HashMap.class);

                // Register user
                ResponseEntity<Map<String, Object>> registrationResponse = register_User(userDetails);

                // Encrypt the response for the Bridge Server
                Map<String, String> encryptedResponse = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(registrationResponse.getBody()), sharedKey);

                return ResponseEntity.ok(Map.of("encryptedData", encryptedResponse));

            } catch (Exception e) {
                System.err.println("[Auth Server] Error in /register: " + e.getMessage());
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Registration failed: " + e.getMessage()));
            }
        }, executorService);
    }

//    /**
//     * Change the password of the current user or another user if the requester is an admin.
//     *
//     * @param passwordDetails A map containing "username", "oldPassword", "newPassword", and optionally "targetUsername" if an admin.
//     * @return A ResponseEntity indicating whether the password was changed successfully.
//     */
//    //current not using endpoint
//    @PostMapping("/changePassword")
//    public CompletableFuture<ResponseEntity<Map<String, Object>>> changePassword(@RequestBody HashMap<String, String> passwordDetails) {
//        return CompletableFuture.supplyAsync(() -> change_Password(passwordDetails), executorService);
//    }
//
//    /**
//     * Update the username of the current user or another user if the requester is an admin.
//     *
//     * @param usernameDetails A map containing the "username", "password", "targetUserId", and "newUsername".
//     * @return A ResponseEntity indicating whether the username update was successful.
//     */
//    //current not using endpoint
//    @PostMapping("/updateUsername")
//    public CompletableFuture<ResponseEntity<Map<String, Object>>> updateUsername(@RequestBody HashMap<String, String> usernameDetails) {
//        return CompletableFuture.supplyAsync(() -> update_Username(usernameDetails), executorService);
//    }
//----------------------------------------Admin only Method----------------------------------------------------------------------------------------
    /**
     * Deletes a user from the system. Only admins can perform this operation.
     *
     * @param encryptedData A encrypted map containing the Admin "username", "password", and the "targetUserId" of the user to delete.
     * @return A ResponseEntity indicating whether the deletion was successful.
     */
    @DeleteMapping("/deleteUser")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> deleteUser(
            @RequestBody Map<String, String> encryptedData, HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Get shared key from session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("[Auth Server] No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                // Decrypt the incoming data
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, Object> deleteDetails = new ObjectMapper().readValue(decryptedData, HashMap.class);
                System.out.println("[Auth Server] Decrypted delete details: " + deleteDetails);

                // Sanitize deleteDetails
                Map<String, String> sanitizedDeleteDetails = deleteDetails.entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> String.valueOf(entry.getValue())
                        ));

                // Proceed with user deletion
                ResponseEntity<Map<String, Object>> deletionResponse = delete_User((HashMap<String, String>) sanitizedDeleteDetails);

                // Encrypt the response properly
                Map<String, String> encryptedResponse = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(deletionResponse.getBody()),
                        sharedKey
                );

                // Return the properly formatted response
                return ResponseEntity.status(deletionResponse.getStatusCode())
                        .body(Map.of("encryptedData", encryptedResponse));

            } catch (Exception e) {
                System.err.println("[Auth Server] Error in /deleteUser: " + e.getMessage());
                e.printStackTrace();
                try {
                    // Encrypt error response
                    Map<String, String> encryptedError = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", "Deletion failed: " + e.getMessage()
                            )),
                            (SecretKey) session.getAttribute("sharedKey")
                    );
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of("encryptedData", encryptedError));
                } catch (Exception encryptError) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of("status", "error", "message", "Encryption failed"));
                }
            }
        }, executorService);
    }

    /**
     * Search all users and return a list of all users with vip and admin status
     *
     * @param encryptedData A enctrpted map containing the "isAdmin" flag for authorization.
     * @return A list that contains the all user information
     */
    @Transactional
    @PostMapping("/listUsers")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> listAllUsers(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Get shared key from session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                // Decrypt request
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, Object> adminDetails = new ObjectMapper().readValue(decryptedData, HashMap.class);

                Boolean isAdmin = (Boolean) adminDetails.get("isAdmin");
                if (isAdmin == null || !isAdmin) {
                    logger.warning("Unauthorized attempt to remove user from group");
                    Map<String, String> errorResponse = Map.of("status", "error", "message", "Not authorized");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(errorResponse),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("encryptedData", encrypted));
                }

                List<User> users = userRepository.findAllWithGroups();
                List<Map<String, Object>> usersList = new ArrayList<>();

                for (User user : users) {
                    Map<String, Object> userInfo = new HashMap<>();
                    userInfo.put("username", user.getUsername());
                    userInfo.put("isVIP", user.isVIP());
                    userInfo.put("isAdmin", user.isAdmin());

                    Set<String> groupNames = new HashSet<>();
                    for (Group group : user.getGroups()) {
                        groupNames.add(group.getGroupName());
                    }
                    userInfo.put("groups", groupNames);
                    usersList.add(userInfo);
                }

                Map<String, Object> response = Map.of(
                        "status", "success",
                        "message", "Users retrieved successfully",
                        "data", usersList
                );

                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(response),
                        sharedKey
                );

                return ResponseEntity.ok(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in listAllUsers: " + e.getMessage());
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to retrieve users"));
            }
        }, executorService);
    }

    /**
     * Search all groups and return a map with group names as keys and users as values.
     *
     * @param encryptedData A encrypted map containing the "isAdmin" flag for authorization.
     * @return A map with group names as keys and lists of users in each group as values.
     */
    @Transactional
    @PostMapping("/listGroups")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> listGroups(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Get shared key from session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                // Decrypt request
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                HashMap adminDetails = new ObjectMapper().readValue(decryptedData, HashMap.class);

                Boolean isAdmin = (Boolean) adminDetails.get("isAdmin");
                if (isAdmin == null || !isAdmin) {
                    logger.warning("Unauthorized attempt to remove user from group");
                    Map<String, String> errorResponse = Map.of("status", "error", "message", "Not authorized");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(errorResponse),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("encryptedData", encrypted));
                }

                List<Group> groups = groupRepository.findAllWithUsers();
                Map<String, List<Map<String, Object>>> groupData = new HashMap<>();

                for (Group group : groups) {
                    List<Map<String, Object>> userList = new ArrayList<>();
                    for (User user : group.getUsers()) {
                        userList.add(Map.of("username", user.getUsername()));
                    }
                    groupData.put(group.getGroupName(), userList);
                }

                Map<String, Object> response = Map.of(
                        "status", "success",
                        "message", "Groups retrieved successfully",
                        "data", groupData
                );

                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(response),
                        sharedKey
                );

                return ResponseEntity.ok(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in listGroups: " + e.getMessage());
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to retrieve groups"));
            }
        }, executorService);
    }

    /**
     * Admin-only method for adding a new user.
     *
     * @param encryptedData A encrypted map containing the username, password, and isVIP flag.
     * @return A ResponseEntity indicating if the user creation was successful.
     */
    @PostMapping("/addUser")
    @Transactional
    public CompletableFuture<ResponseEntity<Map<String, Object>>> addUser(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Get shared key from session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                // Decrypt request
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, String> userDetails = new ObjectMapper().readValue(decryptedData,
                        new TypeReference<Map<String, String>>() {});

                // Process the user creation
                ResponseEntity<Map<String, Object>> result = add_User(userDetails);

                // Encrypt the response
                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(result.getBody()),
                        sharedKey
                );

                return ResponseEntity.status(result.getStatusCode())
                        .body(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in addUser: " + e.getMessage());
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to add user"));
            }
        }, executorService);
    }

//    /**
//     * method for get RSA public key in PEM format
//     */
//    @GetMapping("/publicKey")
//    public CompletableFuture<ResponseEntity<String>> getPublicKey() {
//        return CompletableFuture.supplyAsync(() -> {
//            try {
//                return ResponseEntity.ok(tokenService.getPublicKeyAsPem());
//            } catch (Exception e) {
//                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//                        .body("Error retrieving public key");
//            }
//        }, executorService);
//    }

    //--------------group controller------------------------------------------------------------------------------------
    /**
     * Admin-only method for create the group
     *
     * @param encryptedData A map containing the "isAdmin" and "groupName" flag for authorization and search
     * @return A ResponseEntity indicating if creating is successful
     */
    @PostMapping("/createGroup")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> createGroup(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Get shared key from session
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                // Decrypt request
                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, Object> groupDetails = new ObjectMapper().readValue(decryptedData,
                        new TypeReference<Map<String, Object>>() {});

                Boolean isAdmin = (Boolean) groupDetails.get("isAdmin");
                String groupName = (String) groupDetails.get("groupName");

                if (isAdmin == null || !isAdmin) {
                    logger.warning("Unauthorized attempt to create group");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of("status", "error", "message", "Not authorized")),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("encryptedData", encrypted));
                }

                if (groupName == null || groupName.trim().isEmpty()) {
                    logger.warning("Group name is required");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of("status", "error", "message", "Group name is required")),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(Map.of("encryptedData", encrypted));
                }

                if (groupRepository.findByGroupName(groupName) != null) {
                    logger.warning("Group already exists");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of("status", "error", "message", "Group already exists")),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.CONFLICT)
                            .body(Map.of("encryptedData", encrypted));
                }

                // Create group and save
                Group newGroup = new Group(groupName);
                groupRepository.save(newGroup);

                // Initialize group key with version 0
                try {
                    groupKeyService.initializeGroupKey(newGroup);
                    logger.info("Initialized key for new group: " + groupName + " with version 0");
                } catch (Exception e) {
                    logger.severe("Failed to initialize key for group " + groupName + ": " + e.getMessage());
                    groupRepository.delete(newGroup); // Rollback group creation if key initialization fails
                    throw new RuntimeException("Failed to initialize group key", e);
                }

                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of(
                                "status", "success",
                                "message", "Group created successfully",
                                "groupName", groupName
                        )),
                        sharedKey
                );

                return ResponseEntity.status(HttpStatus.CREATED)
                        .body(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in createGroup: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to create group"));
            }
        }, executorService);
    }

    /**
     * Admin-only method for delete the group
     *
     * @param encryptedData A map containing the "isAdmin" and "groupName" flag for authorization and search
     * @return A ResponseEntity indicating if deleting is successful
     */
    @DeleteMapping("/deleteGroup")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> deleteGroup(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, Object> groupDetails = new ObjectMapper().readValue(decryptedData,
                        new TypeReference<Map<String, Object>>() {});

                Boolean isAdmin = (Boolean) groupDetails.get("isAdmin");
                String groupName = (String) groupDetails.get("groupName");

                if (isAdmin == null || !isAdmin) {
                    logger.warning("Unauthorized attempt to delete group");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of("status", "error", "message", "Not authorized")),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("encryptedData", encrypted));
                }

                Group group = groupRepository.findByGroupName(groupName);
                if (group == null) {
                    logger.warning("Group not found");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of("status", "error", "message", "Group not found")),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("encryptedData", encrypted));
                }

                // First delete all associated keys explicitly
                List<GroupKey> keys = groupKeyRepository.findByGroupOrderByVersionAsc(group);
                groupKeyRepository.deleteAll(keys);

                // Then delete the group
                groupRepository.delete(group);

                // Cleanup any orphaned keys
                groupKeyService.cleanupOrphanedKeys();

                logger.info("Deleted group and its keys: " + groupName);

                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of("status", "success", "message", "Group deleted successfully")),
                        sharedKey
                );

                return ResponseEntity.ok(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in deleteGroup: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to delete group"));
            }
        }, executorService);
    }

    /**
     * Admin-only method for add a user to a group
     *
     * @param encryptedData A map containing the "isAdmin" and "groupName" flag for authorization and search
     *                and "username" to add user to the group
     * @return A ResponseEntity indicating if adding is successful
     */
    @PostMapping("/addUserToGroup")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> addUserToGroup(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, Object> details = new ObjectMapper().readValue(decryptedData,
                        new TypeReference<Map<String, Object>>() {});

                Boolean isAdmin = (Boolean) details.get("isAdmin");
                String username = (String) details.get("username");
                String groupName = (String) details.get("groupName");

                if (isAdmin == null || !isAdmin) {
                    logger.warning("Unauthorized attempt to add user to group");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", "Not authorized to add users to groups"
                            )),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("encryptedData", encrypted));
                }

                User user = userRepository.findByUsernameWithGroups(username);
                Group group = groupRepository.findByGroupName(groupName);

                if (user == null || group == null) {
                    logger.warning("User not found or group not found");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", user == null ? "User not found" : "Group not found"
                            )),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("encryptedData", encrypted));
                }

                if (user.getGroups().contains(group)) {
                    logger.warning("User is already in this group");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", "User is already in this group"
                            )),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.CONFLICT)
                            .body(Map.of("encryptedData", encrypted));
                }
                // Add user to group
                user.getGroups().add(group);
                userRepository.save(user);

                // Rotate group key
                try {
                    int oldVersion = groupKeyService.getLatestKeyVersion(group);
                    groupKeyService.rotateGroupKey(group);
                    int newVersion = groupKeyService.getLatestKeyVersion(group);
                    logger.info("Group " + groupName + " key rotated: version " +
                            oldVersion + " -> " + newVersion + " (user added: " + username + ")");
                } catch (Exception e) {
                    logger.warning("Failed to rotate key for group " + groupName + ": " + e.getMessage());
                    // Continue even if key rotation fails
                }

                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of(
                                "status", "success",
                                "message", "User added to group successfully",
                                "username", username,
                                "groupName", groupName
                        )),
                        sharedKey
                );

                return ResponseEntity.ok(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in addUserToGroup: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to add user to group"));
            }
        }, executorService);
    }

    /**
     * Admin-only method for remove a user from a group
     *
     * @param encryptedData A map containing the "isAdmin" and "groupName" flag for authorization and search
     *                and "username" to remove user from the group
     * @return A ResponseEntity indicating if operation is successful
     */
    @Transactional
    @DeleteMapping("/removeUserFromGroup")
    public CompletableFuture<ResponseEntity<Map<String, Object>>> removeUserFromGroup(
            @RequestBody Map<String, String> encryptedData,
            HttpSession session) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SecretKey sharedKey = (SecretKey) session.getAttribute("sharedKey");
                if (sharedKey == null) {
                    System.err.println("No shared key found in session. Session ID: " + session.getId());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(Map.of("status", "error", "message", "No encryption key established"));
                }

                String decryptedData = diffieHellmanKeyService.decrypt(encryptedData, sharedKey);
                Map<String, Object> details = new ObjectMapper().readValue(decryptedData,
                        new TypeReference<Map<String, Object>>() {});

                Boolean isAdmin = (Boolean) details.get("isAdmin");
                String username = (String) details.get("username");
                String groupName = (String) details.get("groupName");

                if (isAdmin == null || !isAdmin) {
                    logger.warning("Unauthorized attempt to remove user from group");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", "Not authorized to remove users from groups"
                            )),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.FORBIDDEN)
                            .body(Map.of("encryptedData", encrypted));
                }

                User user = userRepository.findByUsernameWithGroups(username);
                Group group = groupRepository.findByGroupName(groupName);

                if (user == null || group == null) {
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", user == null ? "User not found" : "Group not found"
                            )),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("encryptedData", encrypted));
                }

                if (!user.getGroups().contains(group)) {
                    logger.warning("User is not in this group");
                    Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                            new ObjectMapper().writeValueAsString(Map.of(
                                    "status", "error",
                                    "message", "User is not in this group"
                            )),
                            sharedKey
                    );
                    return ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("encryptedData", encrypted));
                }

                // Remove user from group
                user.getGroups().remove(group);
                userRepository.save(user);

                // Rotate group key
                try {
                    int oldVersion = groupKeyService.getLatestKeyVersion(group);
                    groupKeyService.rotateGroupKey(group);
                    int newVersion = groupKeyService.getLatestKeyVersion(group);
                    logger.info("Group " + groupName + " key rotated: version " +
                            oldVersion + " -> " + newVersion + " (user removed: " + username + ")");
                } catch (Exception e) {
                    logger.warning("Failed to rotate key for group " + groupName + ": " + e.getMessage());
                    // Continue even if key rotation fails
                }

                Map<String, String> encrypted = diffieHellmanKeyService.encrypt(
                        new ObjectMapper().writeValueAsString(Map.of(
                                "status", "success",
                                "message", "User removed from group successfully",
                                "username", username,
                                "groupName", groupName
                        )),
                        sharedKey
                );

                return ResponseEntity.ok(Map.of("encryptedData", encrypted));

            } catch (Exception e) {
                System.err.println("Error in removeUserFromGroup: " + e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("status", "error", "message", "Failed to remove user from group"));
            }
        }, executorService);
    }

//    /**
//     * Admin-only method for modify group name
//     *
//     * @param details A map containing the "isAdmin" flag for authorization and
//     *                "oldGroupName" to search the group and "newGroupName" to change the groupName
//     * @return A ResponseEntity indicating if modify group name is successful
//     */
    //  currently not using endpoint
//    @PutMapping("/modifyGroupName")
//    public CompletableFuture<ResponseEntity<Map<String, Object>>> modifyGroupName(@RequestBody Map<String, Object> details) {
//        return CompletableFuture.supplyAsync(() -> {
//            Boolean isAdmin = (Boolean) details.get("isAdmin");
//            String oldGroupName = (String) details.get("oldGroupName");
//            String newGroupName = (String) details.get("newGroupName");
//
//            if (isAdmin == null || !isAdmin) {
//                return createSignedResponse("error", "Not authorized to modify group names", HttpStatus.FORBIDDEN);
//            }
//
//            Group group = groupRepository.findByGroupName(oldGroupName);
//            if (group == null) {
//                return createSignedResponse("error", "Group not found", HttpStatus.NOT_FOUND);
//            }
//
//            if (groupRepository.findByGroupName(newGroupName) != null) {
//                return createSignedResponse("error", "A group with the new name already exists", HttpStatus.CONFLICT);
//            }
//
//            group.setGroupName(newGroupName);
//            groupRepository.save(group);
//
//            return createSignedResponse("success", "Group name modified successfully",
//                    Map.of("oldName", oldGroupName, "newName", newGroupName), HttpStatus.OK);
//        }, executorService);
//    }

    //-----------------------private method--------------------------------------------------------------------
    /*
     * private method for verify user
     * */

    //updated: adding the group key to the response after verify
    private HashMap<String, Object> verify_User(HashMap<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        HashMap<String, Object> response = new HashMap<>();
        response.put("isAuthenticated", false);
        response.put("isVIP", false);
        response.put("isAdmin", false);
        response.put("userID", null);
        response.put("groups", new HashSet<>());
        response.put("groupKeys", new HashMap<>()); // Add groupKeys field
        response.put("status", "error");
        response.put("fingerPrint",server_fp);

        if (username == null || username.trim().isEmpty()) {
            response.put("message", "Username is required");
            return (HashMap<String, Object>) signResponse(response);
        }

        User user = userRepository.findByUsernameWithGroups(username);

        if (user != null && passwordService.verifyPassword(password, user.getPasswordHash())) {
            response.put("status", "success");
            response.put("isAuthenticated", true);
            response.put("isVIP", user.isVIP());
            response.put("isAdmin", user.isAdmin());
            response.put("userID", user.getId());

            Set<String> groupNames = new HashSet<>();
            Map<String, Map<String, String>> groupKeys = new HashMap<>();

            // Process groups and their keys
            for (Group group : user.getGroups()) {
                String groupName = group.getGroupName();
                groupNames.add(groupName);

                // Get all keys for this group
                Map<String, String> keys = groupKeyService.getGroupKeys(group);
                if (!keys.isEmpty()) {
                    groupKeys.put(groupName, keys);
                }
            }

            response.put("groups", groupNames);
            response.put("groupKeys", groupKeys); // Add the group keys to response
        } else {
            response.put("message", "Invalid credentials");
        }
        return (HashMap<String, Object>) signResponse(response);
    }

    /*
     * private method for register
     */
    private ResponseEntity<Map<String, Object>> register_User(Map<String, String> userDetails) {
        String username = userDetails.get("username");
        String password = userDetails.get("password");
        String vipCode = userDetails.get("vipCode");

        System.out.println("Register request received with details: " + userDetails);

        if (username == null || username.trim().isEmpty() || password == null || password.trim().isEmpty()) {
            return createSignedResponse("error", "Username and password are required.", HttpStatus.BAD_REQUEST);
        }

        try {
            User existingUser = userRepository.findByUsername(username);
            if (existingUser != null) {
                System.err.println("Conflict: Username '" + username + "' already exists.");
                return createSignedResponse("error",
                        "The username '" + username + "' already exists. Please choose a different username.",
                        HttpStatus.CONFLICT);
            }

            boolean isVIP = false;
            String vipMessage = "No VIP code provided.";

            if (vipCode != null && !vipCode.trim().isEmpty()) {
                Optional<VipCode> vipCodeOptional = vipCodeRepository.findByCode(vipCode.trim());
                if (vipCodeOptional.isPresent()) {
                    VipCode foundVipCode = vipCodeOptional.get();
                    if (!foundVipCode.isUsed()) {
                        foundVipCode.setUsed(true);
                        vipCodeRepository.save(foundVipCode);
                        isVIP = true;
                        vipMessage = "Valid VIP code used.";
                    } else {
                        vipMessage = "VIP code has already been used.";
                    }
                } else {
                    vipMessage = "Invalid VIP code.";
                }
            }

            System.out.println("Proceeding to hash password and create user.");
            String hashedPassword = passwordService.hashPassword(password);
            User newUser = new User(username, hashedPassword, isVIP, false);
            userRepository.save(newUser);

            Map<String, Object> data = new HashMap<>();
            data.put("username", username);
            data.put("isVIP", isVIP);
            data.put("admin", false);

            System.out.println("User registered successfully: " + data);

            return createSignedResponse("success",
                    "User registered successfully. " + vipMessage,
                    data,
                    HttpStatus.CREATED);

        } catch (Exception e) {
            System.err.println("Error during registration: " + e.getMessage());
            e.printStackTrace(); // Print full stack trace for debugging
            return createSignedResponse("error",
                    "Registration failed due to an unexpected error: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
//
//    /*
//     * private method for change password
//     */
//    private ResponseEntity<Map<String, Object>> change_Password(HashMap<String, String> passwordDetails) {
//        String currentUsername = passwordDetails.get("username");
//        String oldPassword = passwordDetails.get("oldPassword");
//        String newPassword = passwordDetails.get("newPassword");
//        String targetUsername = passwordDetails.get("targetUsername");
//        boolean isAdmin = passwordDetails.get("isAdmin") != null &&
//                Boolean.parseBoolean(passwordDetails.get("isAdmin"));
//
//        if (!isAdmin) {
//            User currentUser = userRepository.findByUsername(currentUsername);
//            if (currentUser == null ||
//                    !passwordService.verifyPassword(oldPassword, currentUser.getPasswordHash())) {
//                return createSignedResponse("error",
//                        "Invalid current username or password.",
//                        HttpStatus.UNAUTHORIZED);
//            }
//
//            if (targetUsername == null || targetUsername.isEmpty()) {
//                try {
//                    currentUser.setPasswordHash(passwordService.hashPassword(newPassword));
//                    userRepository.save(currentUser);
//                    return createSignedResponse("success",
//                            "Password changed successfully for " + currentUser.getUsername(),
//                            Map.of("username", currentUser.getUsername()),
//                            HttpStatus.OK);
//                } catch (Exception e) {
//                    return createSignedResponse("error",
//                            "Error changing password: " + e.getMessage(),
//                            HttpStatus.INTERNAL_SERVER_ERROR);
//                }
//            }
//
//            return createSignedResponse("error",
//                    "You are not authorized to change another user's password.",
//                    HttpStatus.FORBIDDEN);
//        }
//
//        if (targetUsername != null && !targetUsername.isEmpty()) {
//            User targetUser = userRepository.findByUsername(targetUsername);
//
//            if (targetUser == null) {
//                return createSignedResponse("error", "Target user not found.", HttpStatus.NOT_FOUND);
//            }
//
//            if (targetUser.isAdmin()) {
//                return createSignedResponse("error",
//                        "You cannot change the password of another admin.",
//                        HttpStatus.FORBIDDEN);
//            }
//
//            try {
//                targetUser.setPasswordHash(passwordService.hashPassword(newPassword));
//                userRepository.save(targetUser);
//                return createSignedResponse("success",
//                        "Password changed successfully for " + targetUser.getUsername(),
//                        Map.of("username", targetUser.getUsername()),
//                        HttpStatus.OK);
//            } catch (Exception e) {
//                return createSignedResponse("error",
//                        "Error changing password: " + e.getMessage(),
//                        HttpStatus.INTERNAL_SERVER_ERROR);
//            }
//        }
//
//        return createSignedResponse("error",
//                "Target username is required for admins.",
//                HttpStatus.BAD_REQUEST);
//    }
//
//    /*
//     * private method for update username
//     */
//    private ResponseEntity<Map<String, Object>> update_Username(HashMap<String, String> usernameDetails) {
//        String currentUsername = usernameDetails.get("currentUsername");
//        String password = usernameDetails.get("password");
//        String newUsername = usernameDetails.get("newUsername");
//        String targetUsername = usernameDetails.get("targetUsername");
//        boolean isAdmin = Boolean.parseBoolean(usernameDetails.get("isAdmin"));
//
//        if (isAdmin) {
//            if (targetUsername == null || targetUsername.trim().isEmpty()) {
//                return createSignedResponse("error",
//                        "Target username is required for admin.",
//                        HttpStatus.BAD_REQUEST);
//            }
//
//            User targetUser = userRepository.findByUsername(targetUsername);
//            if (targetUser == null) {
//                return createSignedResponse("error",
//                        "Target user not found.",
//                        HttpStatus.NOT_FOUND);
//            }
//
//            if (userRepository.findByUsername(newUsername) != null) {
//                return createSignedResponse("error",
//                        "Username already exists.",
//                        HttpStatus.CONFLICT);
//            }
//
//            try {
//                targetUser.setUsername(newUsername);
//                userRepository.save(targetUser);
//                return createSignedResponse("success",
//                        "Username updated successfully",
//                        Map.of("oldUsername", targetUsername, "newUsername", newUsername),
//                        HttpStatus.OK);
//            } catch (Exception e) {
//                return createSignedResponse("error",
//                        "Error updating username: " + e.getMessage(),
//                        HttpStatus.INTERNAL_SERVER_ERROR);
//            }
//        } else {
//            if (currentUsername == null || password == null) {
//                return createSignedResponse("error",
//                        "Current username and password are required.",
//                        HttpStatus.BAD_REQUEST);
//            }
//
//            User currentUser = userRepository.findByUsername(currentUsername);
//            if (currentUser == null ||
//                    !passwordService.verifyPassword(password, currentUser.getPasswordHash())) {
//                return createSignedResponse("error",
//                        "Invalid current username or password.",
//                        HttpStatus.UNAUTHORIZED);
//            }
//
//            if (userRepository.findByUsername(newUsername) != null) {
//                return createSignedResponse("error",
//                        "Username already exists.",
//                        HttpStatus.CONFLICT);
//            }
//
//            try {
//                currentUser.setUsername(newUsername);
//                userRepository.save(currentUser);
//                return createSignedResponse("success",
//                        "Username updated successfully",
//                        Map.of("oldUsername", currentUsername, "newUsername", newUsername),
//                        HttpStatus.OK);
//            } catch (Exception e) {
//                return createSignedResponse("error",
//                        "Error updating username: " + e.getMessage(),
//                        HttpStatus.INTERNAL_SERVER_ERROR);
//            }
//        }
//    }

    /*
     * private method for delete user
     */

    //update: when delete a user, we check the if there any groups the user belong to, if there are,
    // update the group version and generate new version key
    private ResponseEntity<Map<String, Object>> delete_User(HashMap<String, String> deleteDetails) {
        boolean isAdmin = Boolean.parseBoolean(deleteDetails.get("isAdmin"));
        String targetUsername = deleteDetails.get("targetUsername");

        if (!isAdmin) {
            logger.warning("Unauthorized attempt");
            return createSignedResponse("error",
                    "You are not authorized to delete users.",
                    HttpStatus.FORBIDDEN);
        }

        User targetUser = userRepository.findByUsernameWithGroups(targetUsername);
        if (targetUser == null) {
            logger.warning("User not found");
            return createSignedResponse("error",
                    "User not found.",
                    HttpStatus.NOT_FOUND);
        }

        try {
            // Store groups before deletion for key rotation
            Set<Group> userGroups = new HashSet<>(targetUser.getGroups());

            // Delete the user
            userRepository.delete(targetUser);

            // rotate keys for all groups the user was in
            for (Group group : userGroups) {
                try {
                    int oldVersion = groupKeyService.getLatestKeyVersion(group);
                    groupKeyService.rotateGroupKey(group);
                    int newVersion = groupKeyService.getLatestKeyVersion(group);
                    logger.info("Group " + group.getGroupName() + " key rotated: version " +
                            oldVersion + " -> " + newVersion);
                } catch (Exception e) {
                    logger.warning("Failed to rotate key for group " + group.getGroupName() +
                            ": " + e.getMessage());
                }
            }

            return createSignedResponse("success",
                    "User deleted successfully",
                    Map.of("deletedUsername", targetUsername),
                    HttpStatus.OK);
        } catch (Exception e) {
            return createSignedResponse("error",
                    "Error deleting user: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /*
     * private method for add user
     */
    private ResponseEntity<Map<String, Object>> add_User(Map<String, String> userDetails) {
        String isAdmin = userDetails.get("isAdmin");
        String username = userDetails.get("username");
        String password = userDetails.get("password");
        boolean isVIP = Boolean.parseBoolean(userDetails.get("isVIP"));

        if (!"true".equals(isAdmin)) {
            logger.warning("Unauthorized attempt");
            return createSignedResponse("error",
                    "Only admins can add users.",
                    HttpStatus.FORBIDDEN);
        }

        if (username == null || password == null) {
            logger.warning("Username and password are required");
            return createSignedResponse("error",
                    "Username and password are required.",
                    HttpStatus.BAD_REQUEST);
        }

        if (userRepository.findByUsername(username) != null) {
            logger.warning("Username already exists");
            return createSignedResponse("error",
                    "Username already exists.",
                    HttpStatus.CONFLICT);
        }

        try {
            String hashedPassword = passwordService.hashPassword(password);
            User newUser = new User(username, hashedPassword, isVIP, false);
            userRepository.save(newUser);

            return createSignedResponse("success",
                    "User created successfully.",
                    Map.of(
                            "username", username,
                            "isVIP", isVIP,
                            "isAdmin", false
                    ),
                    HttpStatus.CREATED);
        } catch (Exception e) {
            return createSignedResponse("error",
                    "Error creating user: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
