package com.example.spring.entity;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;


    @Column(name = "is_vip")
    private boolean isVIP;

    @Column(name = "admin")
    private boolean admin;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_group",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id")
    )
    private Set<Group> groups = new HashSet<>();

    // Default constructor
    protected User() {
    }

    // Constructor with parameters
    public User(String username, String passwordHash, boolean isVIP, boolean admin) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.isVIP = isVIP;
        this.admin = admin;
    }
    // Getters
    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public boolean isVIP() {
        return isVIP;
    }

    public boolean isAdmin() {
        return admin;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public void setVIP(boolean VIP) {
        isVIP = VIP;
    }

    // New getter and setter for groups
    public Set<Group> getGroups() {
        return groups;
    }

    public void setGroups(Set<Group> groups) {
        this.groups = groups;
    }

    // Override equals() and hashCode() based on ID
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        User user = (User) o;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    // Override toString()
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", isVIP=" + isVIP +
                ", admin=" + admin +
                ", groups=" + (groups != null ? groups.size() : 0) +
                '}';
    }
}