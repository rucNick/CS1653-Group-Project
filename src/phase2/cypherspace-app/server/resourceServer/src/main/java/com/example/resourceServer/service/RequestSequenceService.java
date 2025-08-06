package com.example.resourceServer.service;

import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RequestSequenceService {
    
    private final ConcurrentHashMap<Long, AtomicInteger> userSequences = new ConcurrentHashMap<>();

    public int getNextSequence(Long userID) {
        AtomicInteger sequence = userSequences.computeIfAbsent(userID, k -> new AtomicInteger(0));
        return sequence.incrementAndGet();
    }

    public int getCurrentSequence(Long userID){
        AtomicInteger sequence = userSequences.computeIfAbsent(userID, k -> new AtomicInteger(0));
        return sequence.get();
    }

    public void getAndIncrement(Long userID){
        AtomicInteger sequence = userSequences.computeIfAbsent(userID, k -> new AtomicInteger(0));
        sequence.incrementAndGet();
    }

}
