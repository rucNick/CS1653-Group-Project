package com.example.resourceServer.entity;

import jakarta.persistence.*;
import java.sql.Blob;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
public class Post {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)  
    private Long postID;
    
    // @Lob
    // @Column(columnDefinition = "BLOB")
    // private byte[] content;

    @Column(columnDefinition = "TEXT")
    private String content;

    private String user;
    private boolean isVIP;

    // @Lob
    // @Column(columnDefinition = "BLOB")
    // private byte[] title;

    @Column(columnDefinition = "TEXT")
    private String title;

    private String groupName;
    private Long userID;
    private Long version;

    public Post() {
        
    }

    public Post(String content, String user, boolean isVIP, String title, String groupName, long userID, long version) {
        this.content = content;
        this.user = user;
        this.isVIP = isVIP;
        this.title = title;
        this.groupName = groupName;
        this.userID = userID;
        this.version = version;
    }

    // Getters and Setters
    public Long getPostID() {
        return postID; 
    }

    public void setPostID(Long postID) {
         this.postID = postID; 
    }

    public String getContent() {
        return content; 
    }
    public void setContent(String content) {
        this.content = content; 
    }

    public String getUser() { 
        return user; 
    }
    public void setUser(String user) { 
        this.user = user; 
    }

    public boolean isVIP() { 
        return isVIP; 
    }
    public void setVIP(boolean isVIP) { 
        this.isVIP = isVIP; 
    }

    public String getTitle() { 
        return title; 
    }
    public void setTitle(String title) { 
        this.title = title; 
    }

    public String getGroupName(){
        return groupName;
    }
    public void setGroup(String groupName){
        this.groupName = groupName;
    }

    public Long getUserId(){
        return userID;
    }
    public void setUserId(Long userID){
        this.userID = userID;
    }

    public Long getVersion(){
        return version;
    }
    public void setVersion(Long version){
        this.version = version;
    }


    // Add methods to handle encrypted objects
    @JsonIgnore
    public EncryptedObject getTitleObject() {
        try {
            return new ObjectMapper().readValue(this.title, EncryptedObject.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error deserializing title object", e);
        }
    }

    public void setTitleObject(EncryptedObject titleObj) {
        try {
            this.title = new ObjectMapper().writeValueAsString(titleObj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error serializing title object", e);
        }
    }

    @JsonIgnore
    public EncryptedObject getContentObject() {
        try {
            return new ObjectMapper().readValue(this.content, EncryptedObject.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error deserializing content object", e);
        }
    }

    public void setContentObject(EncryptedObject contentObj) {
        try {
            this.content = new ObjectMapper().writeValueAsString(contentObj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error serializing content object", e);
        }
    }

}