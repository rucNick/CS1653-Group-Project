package com.example.spring.repository;

import com.example.spring.entity.VipCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VipCodeRepository extends JpaRepository<VipCode, Long> {
    Optional<VipCode> findByCode(String code);
}