package com.example.resourceServer.repository;

import com.example.resourceServer.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    
    // Custom method to retrieve posts where isVIP is false
    List<Post> findByIsVIPFalse();

    // Method to retrieve posts by a certain groupName
    List<Post> findByGroupName(String groupName);

    @Query("SELECT p FROM Post p where p.groupName IN (:groupNames)")
    List<Post> findByGroupNameIn(@Param("groupNames") List<String> groupNames);

    // Method to get posts by userID
    List<Post> findByUserID(Long userID);

    List<Post> findByIsVIPFalseAndGroupNameIgnoreCase(String groupName);

    // Goes through and deletes all posts belonging to one user
    @Transactional
    void deleteByUserID(Long userID);

    // Checks if there are post by a certain userID
    boolean existsByUserID(Long userID);

}