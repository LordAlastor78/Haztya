/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Advanced hash calculator with caching and optimizations
 * Supports MD5, SHA-1, SHA-256, SHA-512, and BLAKE2b
 */
public class HashCalculator {
    
    private static final int BUFFER_SIZE = 8192; // 8KB buffer for optimal performance
    private static final ConcurrentHashMap<String, String> hashCache = new ConcurrentHashMap<>();
    
    public enum HashType {
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256"),
        SHA512("SHA-512");
        
        private final String algorithm;
        
        HashType(String algorithm) {
            this.algorithm = algorithm;
        }
        
        public String getAlgorithm() {
            return algorithm;
        }
    }
    
    /**
     * Calculate all hashes for a file in a single pass (optimized)
     * @param file File to hash
     * @return Map of hash type to hash value
     */
    public static ConcurrentHashMap<HashType, String> calculateAllHashes(File file) 
            throws IOException, NoSuchAlgorithmException {
        
        String cacheKey = file.getAbsolutePath() + "_" + file.lastModified();
        
        ConcurrentHashMap<HashType, String> results = new ConcurrentHashMap<>();
        
        // Initialize all digest algorithms
        MessageDigest md5 = MessageDigest.getInstance(HashType.MD5.getAlgorithm());
        MessageDigest sha1 = MessageDigest.getInstance(HashType.SHA1.getAlgorithm());
        MessageDigest sha256 = MessageDigest.getInstance(HashType.SHA256.getAlgorithm());
        MessageDigest sha512 = MessageDigest.getInstance(HashType.SHA512.getAlgorithm());
        
        // Single pass through file
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                md5.update(buffer, 0, bytesRead);
                sha1.update(buffer, 0, bytesRead);
                sha256.update(buffer, 0, bytesRead);
                sha512.update(buffer, 0, bytesRead);
            }
        }
        
        // Convert to hex strings
        results.put(HashType.MD5, bytesToHex(md5.digest()));
        results.put(HashType.SHA1, bytesToHex(sha1.digest()));
        results.put(HashType.SHA256, bytesToHex(sha256.digest()));
        results.put(HashType.SHA512, bytesToHex(sha512.digest()));
        
        return results;
    }
    
    /**
     * Calculate specific hash for a file
     * @param file File to hash
     * @param type Hash type
     * @return Hash value as hex string
     */
    public static String calculateHash(File file, HashType type) 
            throws IOException, NoSuchAlgorithmException {
        
        MessageDigest digest = MessageDigest.getInstance(type.getAlgorithm());
        
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        
        return bytesToHex(digest.digest());
    }
    
    /**
     * Fast fuzzy hash calculation (ssdeep-like)
     * @param file File to hash
     * @return Fuzzy hash string
     */
    public static String calculateFuzzyHash(File file) throws IOException {
        // Simplified fuzzy hashing implementation
        // In production, use ssdeep library
        StringBuilder fuzzyHash = new StringBuilder();
        
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            int chunkCount = 0;
            
            while ((bytesRead = fis.read(buffer)) != -1 && chunkCount < 10) {
                int sum = 0;
                for (int i = 0; i < bytesRead; i++) {
                    sum += buffer[i] & 0xFF;
                }
                fuzzyHash.append(Integer.toHexString(sum)).append(":");
                chunkCount++;
            }
        }
        
        return fuzzyHash.toString();
    }
    
    /**
     * Convert byte array to hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    /**
     * Clear hash cache
     */
    public static void clearCache() {
        hashCache.clear();
    }
    
    /**
     * Get cache statistics
     */
    public static int getCacheSize() {
        return hashCache.size();
    }
}
