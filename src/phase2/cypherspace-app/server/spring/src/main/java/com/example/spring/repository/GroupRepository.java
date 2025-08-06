package com.example.spring.repository;

import com.example.spring.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GroupRepository extends JpaRepository<Group, Long> {
    Group findByGroupName(String groupName);

    @Query("SELECT g FROM Group g LEFT JOIN FETCH g.users")
    List<Group> findAllWithUsers();

}

