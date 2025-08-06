package com.example.spring.repository;

import com.example.spring.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.groups")
    List<User> findAllWithGroups();

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.groups WHERE u.username = :username")
    User findByUsernameWithGroups(@Param("username") String username);
}