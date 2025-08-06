package com.example.spring.config;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

@Component
public class ShutdownHookConfig {

    private final ApplicationContext applicationContext;

    public ShutdownHookConfig(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
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
            System.out.println("Cleanup completed. Shutdown successful.");
        } catch (Exception e) {
            System.err.println("Error during shutdown: " + e.getMessage());
        }
    }
}
