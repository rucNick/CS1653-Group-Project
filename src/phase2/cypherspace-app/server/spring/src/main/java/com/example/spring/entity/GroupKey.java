package com.example.spring.entity;
import jakarta.persistence.*;

@Entity
@Table(name = "group_keys")
public class GroupKey {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id", nullable = false)
    private Group group;

    @Column(nullable = false)
    private String keyValue;

    @Column(nullable = false)
    private int version;

    // Default constructor
    public GroupKey() {}

    // Constructor with parameters
    public GroupKey(Group group, String keyValue, int version) {
        this.group = group;
        this.keyValue = keyValue;
        this.version = version;
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public String getKeyValue() {
        return keyValue;
    }

    public void setKeyValue(String keyValue) {
        this.keyValue = keyValue;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }
}