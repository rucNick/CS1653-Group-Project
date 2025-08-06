package com.example.resourceServer.entity;

public class EncryptedObject {
    private String encrypted;
    private String iv;
    private String authTag;

    // Default constructor
    public EncryptedObject() {}

    public EncryptedObject(String encrypted, String iv, String authTag) {
        this.encrypted = encrypted;
        this.iv = iv;
        this.authTag = authTag;
    }

    // Getters and setters
    public String getEncrypted() { return encrypted; }
    public void setEncrypted(String encrypted) { this.encrypted = encrypted; }
    
    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }
    
    public String getAuthTag() { return authTag; }
    public void setAuthTag(String authTag) { this.authTag = authTag; }
}