/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.realtime;

import android.os.FileObserver;
import androidx.annotation.Nullable;

import com.haztya.scanner.engine.ScanEngine;
import com.haztya.scanner.engine.ScanResult;

import java.io.File;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Advanced recursive file observer for real-time scanning
 * Monitors file system changes and triggers scans automatically
 */
public class RealtimeMonitor {
    
    private final ScanEngine scanEngine;
    private final ExecutorService scanExecutor;
    private final ConcurrentHashMap<String, FileObserver> observers;
    private final ConcurrentHashMap<String, Long> recentScans;
    
    private boolean isMonitoring = false;
    private RealtimeListener listener;
    
    private static final int SCAN_COOLDOWN_MS = 2000; // 2 seconds cooldown per file
    private static final int OBSERVER_EVENTS = 
        FileObserver.CREATE | 
        FileObserver.MODIFY | 
        FileObserver.MOVED_TO | 
        FileObserver.CLOSE_WRITE;
    
    public RealtimeMonitor(ScanEngine scanEngine) {
        this.scanEngine = scanEngine;
        this.scanExecutor = Executors.newFixedThreadPool(
            Runtime.getRuntime().availableProcessors() / 2
        );
        this.observers = new ConcurrentHashMap<>();
        this.recentScans = new ConcurrentHashMap<>();
    }
    
    /**
     * Start monitoring a directory recursively
     */
    public void startMonitoring(File directory) {
        if (!directory.exists() || !directory.isDirectory()) {
            notifyError("Invalid directory: " + directory.getAbsolutePath());
            return;
        }
        
        isMonitoring = true;
        monitorDirectoryRecursive(directory);
        notifyMonitoringStarted(directory);
    }
    
    /**
     * Monitor directory and all subdirectories recursively
     */
    private void monitorDirectoryRecursive(File directory) {
        if (directory == null || !directory.isDirectory()) return;
        
        String path = directory.getAbsolutePath();
        
        // Create file observer for this directory
        FileObserver observer = new FileObserver(path, OBSERVER_EVENTS) {
            @Override
            public void onEvent(int event, @Nullable String fileName) {
                if (fileName == null) return;
                
                File file = new File(directory, fileName);
                
                // Handle different events
                switch (event & FileObserver.ALL_EVENTS) {
                    case FileObserver.CREATE:
                    case FileObserver.MODIFY:
                    case FileObserver.MOVED_TO:
                    case FileObserver.CLOSE_WRITE:
                        handleFileEvent(file, event);
                        break;
                }
            }
        };
        
        observer.startWatching();
        observers.put(path, observer);
        
        // Recursively monitor subdirectories
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    monitorDirectoryRecursive(file);
                }
            }
        }
    }
    
    /**
     * Handle file system event
     */
    private void handleFileEvent(File file, int event) {
        if (!file.exists() || !file.isFile()) return;
        
        String path = file.getAbsolutePath();
        
        // Check cooldown to avoid scanning same file repeatedly
        Long lastScan = recentScans.get(path);
        long currentTime = System.currentTimeMillis();
        
        if (lastScan != null && (currentTime - lastScan) < SCAN_COOLDOWN_MS) {
            return; // Skip, file was recently scanned
        }
        
        // Update last scan time
        recentScans.put(path, currentTime);
        
        // Submit scan task
        scanExecutor.submit(() -> {
            try {
                ScanResult result = scanEngine.scanFile(file);
                
                if (result.isThreat()) {
                    notifyThreatDetected(file, result);
                }
                
            } catch (Exception e) {
                notifyError("Error scanning file: " + e.getMessage());
            }
        });
    }
    
    /**
     * Stop monitoring
     */
    public void stopMonitoring() {
        isMonitoring = false;
        
        // Stop all observers
        for (FileObserver observer : observers.values()) {
            observer.stopWatching();
        }
        observers.clear();
        
        // Clear recent scans cache
        recentScans.clear();
        
        // Shutdown executor
        scanExecutor.shutdown();
        
        notifyMonitoringStopped();
    }
    
    /**
     * Set realtime listener
     */
    public void setListener(RealtimeListener listener) {
        this.listener = listener;
    }
    
    // Notification methods
    private void notifyMonitoringStarted(File directory) {
        if (listener != null) {
            listener.onMonitoringStarted(directory);
        }
    }
    
    private void notifyMonitoringStopped() {
        if (listener != null) {
            listener.onMonitoringStopped();
        }
    }
    
    private void notifyThreatDetected(File file, ScanResult result) {
        if (listener != null) {
            listener.onThreatDetected(file, result);
        }
    }
    
    private void notifyError(String error) {
        if (listener != null) {
            listener.onError(error);
        }
    }
    
    public boolean isMonitoring() {
        return isMonitoring;
    }
    
    /**
     * Realtime monitoring listener interface
     */
    public interface RealtimeListener {
        void onMonitoringStarted(File directory);
        void onMonitoringStopped();
        void onThreatDetected(File file, ScanResult result);
        void onError(String error);
    }
}
