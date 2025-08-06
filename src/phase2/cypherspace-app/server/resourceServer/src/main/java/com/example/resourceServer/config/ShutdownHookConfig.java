package com.example.resourceServer.config;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class ShutdownHookConfig {

    @Autowired
    private ApplicationContext applicationContext;

    private final ExecutorService executorService;

    public ShutdownHookConfig(ExecutorService executorService) {
        this.executorService = executorService;
    }

    // Register the shutdown hook
    @PostConstruct
    public void setupShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutdown hook triggered. Performing cleanup...");
            performCleanup();
        }));
    }

    // Ensure cleanup also happens on context destroy
    @PreDestroy
    public void onDestroy() {
        System.out.println("PreDestroy invoked: Releasing resources...");
        performCleanup();
    }

    // Perform necessary cleanup operations
    private void performCleanup() {
        try {
            // Stop accepting new requests gracefully
            System.out.println("Shutting down web server context...");
            if (applicationContext instanceof AutoCloseable) {
                ((AutoCloseable) applicationContext).close();
            }

            //thread pool is properly shut down
            shutdownThreadPool();

            System.out.println("Cleanup completed. Shutdown successful.");
        } catch (Exception e) {
            System.err.println("Error during shutdown: " + e.getMessage());
        }
    }

    // Gracefully shutdown the thread pool
    private void shutdownThreadPool() {
        System.out.println("Shutting down thread pool...");
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                System.out.println("Forcing thread pool shutdown...");
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            System.err.println("Thread pool shutdown interrupted: " + e.getMessage());
            executorService.shutdownNow();
        }
    }

}
