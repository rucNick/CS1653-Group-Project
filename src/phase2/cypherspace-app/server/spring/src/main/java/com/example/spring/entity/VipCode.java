package com.example.spring.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "vip_code")
public class VipCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "Code", nullable = false, unique = true)
    private String code;

    @Column(name = "Used", nullable = false)
    private boolean isUsed;

    // Default constructor
    public VipCode() {
    }

    // Constructor with parameters
    public VipCode(String code) {
        this.code = code;
        this.isUsed = false;
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public boolean isUsed() {
        return isUsed;
    }

    public void setUsed(boolean used) {
        isUsed = used;
    }
}