package com.example.spring.entity;

import jakarta.persistence.*;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "groups")
public class Group {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "group_name", unique = true, nullable = false)
    private String groupName;  // Changed from 'name' to 'groupName'

    @ManyToMany(mappedBy = "groups", fetch = FetchType.LAZY)
    private Set<User> users = new HashSet<>();

    // Default constructor
    protected Group() {}

    // Constructor with groupName
    public Group(String groupName) {
        this.groupName = groupName;
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public String getGroupName() {  // Changed from 'getName' to 'getGroupName'
        return groupName;
    }

    public void setGroupName(String groupName) {  // Changed from 'setName' to 'setGroupName'
        this.groupName = groupName;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    // Override equals() and hashCode() based on ID
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group group = (Group) o;
        return Objects.equals(id, group.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    // Override toString()
    @Override
    public String toString() {
        return "Group{" +
                "id=" + id +
                ", groupName='" + groupName + '\'' +
                ", users=" + (users != null ? users.size() : 0) +
                '}';
    }
}