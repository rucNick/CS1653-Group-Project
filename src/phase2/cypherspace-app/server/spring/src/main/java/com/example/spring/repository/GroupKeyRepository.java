package com.example.spring.repository;

import com.example.spring.entity.Group;
import com.example.spring.entity.GroupKey;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

public interface GroupKeyRepository extends JpaRepository<GroupKey, Long> {
    // Find all keys for a group ordered by version
    List<GroupKey> findByGroupOrderByVersionAsc(Group group);

    // Find specific version of a group's key
    GroupKey findByGroupAndVersion(Group group, int version);

    // Count total keys for a group (used for versioning)
    @Query("SELECT COUNT(gk) FROM GroupKey gk WHERE gk.group = :group")
    Integer getKeyCountForGroup(@Param("group") Group group);

    @Query("DELETE FROM GroupKey gk WHERE gk.group.id NOT IN (SELECT g.id FROM Group g)")
    @Modifying
    @Transactional
    void deleteOrphanedKeys();

}

