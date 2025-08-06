package com.example.spring.service;

import com.example.spring.entity.Group;
import com.example.spring.entity.GroupKey;
import com.example.spring.repository.GroupKeyRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

@Service
public class GroupKeyService {
    @Autowired
    private GroupKeyRepository groupKeyRepository;

    private static final int KEY_SIZE = 256;

    // Generate a new key for a group
    public String generateNewGroupKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(KEY_SIZE, new SecureRandom());
        SecretKey key = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Initialize a new group with its first key (version 0)
    public void initializeGroupKey(Group group) {
        try {
            String key = generateNewGroupKey();
            GroupKey groupKey = new GroupKey(group, key, 0);
            groupKeyRepository.save(groupKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize group key", e);
        }
    }

    // Generate a new key version when removing a user
    public void rotateGroupKey(Group group) {
        try {
            // Get current version (array size)
            Integer currentVersion = groupKeyRepository.getKeyCountForGroup(group);
            if (currentVersion == null) {
                currentVersion = 0;
            }

            // Generate and save new key
            String newKey = generateNewGroupKey();
            GroupKey groupKey = new GroupKey(group, newKey, currentVersion);
            groupKeyRepository.save(groupKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to rotate group key", e);
        }
    }

    // Get all keys for a group
    public Map<String, String> getGroupKeys(Group group) {
        List<GroupKey> keys = groupKeyRepository.findByGroupOrderByVersionAsc(group);
        Map<String, String> keyVersions = new HashMap<>();

        for (GroupKey key : keys) {
            keyVersions.put(String.valueOf(key.getVersion()), key.getKeyValue());
        }

        return keyVersions;
    }

    // Get latest version number for a group
    public int getLatestKeyVersion(Group group) {
        Integer count = groupKeyRepository.getKeyCountForGroup(group);
        return count != null ? count - 1 : 0;
    }

    @Transactional
    public void cleanupOrphanedKeys() {
        groupKeyRepository.deleteOrphanedKeys();
    }
}