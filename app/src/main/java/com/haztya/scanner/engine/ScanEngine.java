/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.engine;

import com.haztya.scanner.core.HashCalculator;
import com.haztya.scanner.core.MalwareSignature;
import com.haztya.scanner.core.SignatureDatabase;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Advanced multi-threaded malware scanner engine
 * Features:
 * - Multi-threaded parallel scanning
 * - Multiple detection algorithms
 * - Heuristic analysis
 * - Real-time scanning capability
 * - Smart file prioritization
 */
public class ScanEngine {
    
    private final SignatureDatabase signatureDatabase;
    private final ExecutorService executorService;
    private final BlockingQueue<ScanTask> scanQueue;
    private final List<ScanListener> listeners;
    
    private final AtomicInteger filesScanned;
    private final AtomicInteger threatsDetected;
    private final AtomicLong bytesScanned;
    
    private boolean isScanning = false;
    private long scanStartTime;
    
    private static final int THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final long MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB default
    
    // Heuristic thresholds
    private static final double ENTROPY_THRESHOLD = 7.5; // High entropy = potential encryption/packing
    private static final int SUSPICIOUS_EXTENSION_SCORE = 50;
    
    public ScanEngine(SignatureDatabase signatureDatabase) {
        this.signatureDatabase = signatureDatabase;
        this.executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        this.scanQueue = new LinkedBlockingQueue<>();
        this.listeners = new ArrayList<>();
        this.filesScanned = new AtomicInteger(0);
        this.threatsDetected = new AtomicInteger(0);
        this.bytesScanned = new AtomicLong(0);
    }
    
    /**
     * Start scanning files
     */
    public void startScan(List<File> files) {
        if (isScanning) {
            notifyError("Scan already in progress");
            return;
        }
        
        isScanning = true;
        scanStartTime = System.currentTimeMillis();
        filesScanned.set(0);
        threatsDetected.set(0);
        bytesScanned.set(0);
        
        notifyScanStarted(files.size());
        
        // Submit scan tasks
        for (File file : files) {
            if (file.exists() && file.isFile()) {
                executorService.submit(() -> scanFile(file));
            }
        }
    }
    
    /**
     * Scan a single file with multiple detection methods
     */
    public ScanResult scanFile(File file) {
        if (file == null || !file.exists() || !file.canRead()) {
            return new ScanResult(file, ScanResult.Status.ERROR, "File not accessible");
        }
        
        // Skip very large files
        if (file.length() > MAX_FILE_SIZE) {
            return new ScanResult(file, ScanResult.Status.SKIPPED, "File too large");
        }
        
        try {
            ScanResult result = new ScanResult(file);
            
            // 1. Signature-based detection
            MalwareSignature signature = performSignatureCheck(file);
            if (signature != null) {
                result.setStatus(ScanResult.Status.THREAT_DETECTED);
                result.setThreat(signature);
                result.setDetectionMethod("Signature Match");
                threatsDetected.incrementAndGet();
                notifyThreatDetected(result);
            }
            
            // 2. Heuristic analysis
            else if (performHeuristicAnalysis(file, result)) {
                result.setStatus(ScanResult.Status.SUSPICIOUS);
                notifyThreatDetected(result);
            }
            
            // 3. Behavioral analysis (for APKs)
            else if (file.getName().endsWith(".apk")) {
                performApkAnalysis(file, result);
            }
            
            else {
                result.setStatus(ScanResult.Status.CLEAN);
            }
            
            // Update statistics
            filesScanned.incrementAndGet();
            bytesScanned.addAndGet(file.length());
            
            notifyProgress(filesScanned.get());
            
            return result;
            
        } catch (Exception e) {
            return new ScanResult(file, ScanResult.Status.ERROR, e.getMessage());
        }
    }
    
    /**
     * Perform signature-based detection
     */
    private MalwareSignature performSignatureCheck(File file) {
        try {
            ConcurrentHashMap<HashCalculator.HashType, String> hashes = 
                HashCalculator.calculateAllHashes(file);
            
            // Check each hash type
            for (HashCalculator.HashType type : HashCalculator.HashType.values()) {
                String hash = hashes.get(type);
                if (signatureDatabase.mightContain(hash, type)) {
                    MalwareSignature signature = signatureDatabase.getSignature(hash, type);
                    if (signature != null) {
                        return signature;
                    }
                }
            }
        } catch (Exception e) {
            // Log error
        }
        return null;
    }
    
    /**
     * Perform heuristic analysis
     */
    private boolean performHeuristicAnalysis(File file, ScanResult result) {
        int suspicionScore = 0;
        List<String> indicators = new ArrayList<>();
        
        try {
            // 1. Check file entropy (high entropy = packed/encrypted)
            double entropy = calculateEntropy(file);
            if (entropy > ENTROPY_THRESHOLD) {
                suspicionScore += 30;
                indicators.add("High entropy detected: " + String.format("%.2f", entropy));
            }
            
            // 2. Check suspicious extensions
            String fileName = file.getName().toLowerCase();
            String[] suspiciousExtensions = {".exe", ".scr", ".bat", ".cmd", ".vbs", ".js"};
            for (String ext : suspiciousExtensions) {
                if (fileName.endsWith(ext)) {
                    suspicionScore += SUSPICIOUS_EXTENSION_SCORE;
                    indicators.add("Suspicious extension: " + ext);
                    break;
                }
            }
            
            // 3. Check for double extensions
            if (fileName.matches(".*\\.[a-z]{2,4}\\.[a-z]{2,4}$")) {
                suspicionScore += 40;
                indicators.add("Double extension detected");
            }
            
            // 4. Check file size anomalies
            if (file.length() < 100) {
                suspicionScore += 20;
                indicators.add("Suspiciously small file");
            }
            
            result.setHeuristicScore(suspicionScore);
            result.setSuspicionIndicators(indicators);
            
            return suspicionScore > 50; // Threshold for suspicion
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Calculate Shannon entropy of file
     */
    private double calculateEntropy(File file) {
        try {
            int[] frequency = new int[256];
            int totalBytes = 0;
            
            byte[] buffer = new byte[8192];
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1 && totalBytes < 1024 * 1024) { // Sample first 1MB
                for (int i = 0; i < bytesRead; i++) {
                    frequency[buffer[i] & 0xFF]++;
                    totalBytes++;
                }
            }
            fis.close();
            
            double entropy = 0.0;
            for (int count : frequency) {
                if (count > 0) {
                    double probability = (double) count / totalBytes;
                    entropy -= probability * (Math.log(probability) / Math.log(2));
                }
            }
            
            return entropy;
            
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    /**
     * Perform APK-specific analysis
     */
    private void performApkAnalysis(File apkFile, ScanResult result) {
        // TODO: Implement APK analysis
        // - Check permissions
        // - Analyze AndroidManifest.xml
        // - Check for suspicious code patterns
        // - Verify signature
    }
    
    /**
     * Stop scanning
     */
    public void stopScan() {
        isScanning = false;
        executorService.shutdownNow();
        try {
            executorService.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        notifyScanCompleted();
    }
    
    /**
     * Add scan listener
     */
    public void addListener(ScanListener listener) {
        listeners.add(listener);
    }
    
    // Notification methods
    private void notifyScanStarted(int totalFiles) {
        for (ScanListener listener : listeners) {
            listener.onScanStarted(totalFiles);
        }
    }
    
    private void notifyProgress(int filesScanned) {
        for (ScanListener listener : listeners) {
            listener.onProgress(filesScanned, bytesScanned.get());
        }
    }
    
    private void notifyThreatDetected(ScanResult result) {
        for (ScanListener listener : listeners) {
            listener.onThreatDetected(result);
        }
    }
    
    private void notifyScanCompleted() {
        long duration = System.currentTimeMillis() - scanStartTime;
        for (ScanListener listener : listeners) {
            listener.onScanCompleted(filesScanned.get(), threatsDetected.get(), duration);
        }
    }
    
    private void notifyError(String error) {
        for (ScanListener listener : listeners) {
            listener.onError(error);
        }
    }
    
    // Getters
    public boolean isScanning() { return isScanning; }
    public int getFilesScanned() { return filesScanned.get(); }
    public int getThreatsDetected() { return threatsDetected.get(); }
    public long getBytesScanned() { return bytesScanned.get(); }
    
    /**
     * Scan task for queue
     */
    private static class ScanTask {
        final File file;
        final int priority;
        
        ScanTask(File file, int priority) {
            this.file = file;
            this.priority = priority;
        }
    }
    
    /**
     * Scan listener interface
     */
    public interface ScanListener {
        void onScanStarted(int totalFiles);
        void onProgress(int filesScanned, long bytesScanned);
        void onThreatDetected(ScanResult result);
        void onScanCompleted(int totalFiles, int threatsFound, long duration);
        void onError(String error);
    }
}
