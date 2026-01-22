/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.core;

import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Advanced signature database manager with multiple data structures
 * Uses BloomFilters for fast lookups and HashMaps for precise matching
 */
public class SignatureDatabase {
    
    private BloomFilter<String> bloomFilterMD5;
    private BloomFilter<String> bloomFilterSHA1;
    private BloomFilter<String> bloomFilterSHA256;
    private BloomFilter<String> bloomFilterDomains;
    
    // Precise hash maps for confirmed matches
    private final ConcurrentHashMap<String, MalwareSignature> preciseSignaturesMD5;
    private final ConcurrentHashMap<String, MalwareSignature> preciseSignaturesSHA1;
    private final ConcurrentHashMap<String, MalwareSignature> preciseSignaturesSHA256;
    
    // YARA-like pattern matching (simplified)
    private final ConcurrentHashMap<String, String> yaraPatterns;
    
    private long signatureCount = 0;
    private boolean isLoaded = false;
    
    private static final int EXPECTED_INSERTIONS = 10_000_000;
    private static final double FALSE_POSITIVE_RATE = 0.001; // 0.1%
    
    public SignatureDatabase() {
        preciseSignaturesMD5 = new ConcurrentHashMap<>();
        preciseSignaturesSHA1 = new ConcurrentHashMap<>();
        preciseSignaturesSHA256 = new ConcurrentHashMap<>();
        yaraPatterns = new ConcurrentHashMap<>();
        
        initializeBloomFilters();
    }
    
    private void initializeBloomFilters() {
        bloomFilterMD5 = BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8),
            EXPECTED_INSERTIONS,
            FALSE_POSITIVE_RATE
        );
        
        bloomFilterSHA1 = BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8),
            EXPECTED_INSERTIONS,
            FALSE_POSITIVE_RATE
        );
        
        bloomFilterSHA256 = BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8),
            EXPECTED_INSERTIONS,
            FALSE_POSITIVE_RATE
        );
        
        bloomFilterDomains = BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8),
            EXPECTED_INSERTIONS / 10,
            FALSE_POSITIVE_RATE
        );
    }
    
    /**
     * Add signature to database
     */
    public void addSignature(MalwareSignature signature) {
        if (signature.getMd5() != null && !signature.getMd5().isEmpty()) {
            bloomFilterMD5.put(signature.getMd5().toLowerCase());
            preciseSignaturesMD5.put(signature.getMd5().toLowerCase(), signature);
        }
        
        if (signature.getSha1() != null && !signature.getSha1().isEmpty()) {
            bloomFilterSHA1.put(signature.getSha1().toLowerCase());
            preciseSignaturesSHA1.put(signature.getSha1().toLowerCase(), signature);
        }
        
        if (signature.getSha256() != null && !signature.getSha256().isEmpty()) {
            bloomFilterSHA256.put(signature.getSha256().toLowerCase());
            preciseSignaturesSHA256.put(signature.getSha256().toLowerCase(), signature);
        }
        
        signatureCount++;
    }
    
    /**
     * Check if hash might be malicious (fast check using BloomFilter)
     */
    public boolean mightContain(String hash, HashCalculator.HashType type) {
        if (hash == null || hash.isEmpty()) return false;
        
        hash = hash.toLowerCase();
        
        switch (type) {
            case MD5:
                return bloomFilterMD5.mightContain(hash);
            case SHA1:
                return bloomFilterSHA1.mightContain(hash);
            case SHA256:
                return bloomFilterSHA256.mightContain(hash);
            default:
                return false;
        }
    }
    
    /**
     * Get precise malware signature if exists
     */
    public MalwareSignature getSignature(String hash, HashCalculator.HashType type) {
        if (hash == null || hash.isEmpty()) return null;
        
        hash = hash.toLowerCase();
        
        switch (type) {
            case MD5:
                return preciseSignaturesMD5.get(hash);
            case SHA1:
                return preciseSignaturesSHA1.get(hash);
            case SHA256:
                return preciseSignaturesSHA256.get(hash);
            default:
                return null;
        }
    }
    
    /**
     * Add malicious domain to database
     */
    public void addMaliciousDomain(String domain) {
        if (domain != null && !domain.isEmpty()) {
            bloomFilterDomains.put(domain.toLowerCase());
        }
    }
    
    /**
     * Check if domain might be malicious
     */
    public boolean isDomainMalicious(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        return bloomFilterDomains.mightContain(domain.toLowerCase());
    }
    
    /**
     * Save database to file
     */
    public void saveToDisk(File outputFile) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(outputFile))) {
            oos.writeObject(bloomFilterMD5);
            oos.writeObject(bloomFilterSHA1);
            oos.writeObject(bloomFilterSHA256);
            oos.writeObject(bloomFilterDomains);
            oos.writeLong(signatureCount);
        }
    }
    
    /**
     * Load database from file
     */
    @SuppressWarnings("unchecked")
    public void loadFromDisk(File inputFile) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(inputFile))) {
            bloomFilterMD5 = (BloomFilter<String>) ois.readObject();
            bloomFilterSHA1 = (BloomFilter<String>) ois.readObject();
            bloomFilterSHA256 = (BloomFilter<String>) ois.readObject();
            bloomFilterDomains = (BloomFilter<String>) ois.readObject();
            signatureCount = ois.readLong();
            isLoaded = true;
        }
    }
    
    /**
     * Get database statistics
     */
    public DatabaseStats getStats() {
        return new DatabaseStats(
            signatureCount,
            preciseSignaturesMD5.size(),
            preciseSignaturesSHA1.size(),
            preciseSignaturesSHA256.size(),
            (long) bloomFilterMD5.approximateElementCount(),
            isLoaded
        );
    }
    
    public long getSignatureCount() {
        return signatureCount;
    }
    
    public boolean isLoaded() {
        return isLoaded;
    }
    
    /**
     * Clear all signatures
     */
    public void clear() {
        preciseSignaturesMD5.clear();
        preciseSignaturesSHA1.clear();
        preciseSignaturesSHA256.clear();
        yaraPatterns.clear();
        initializeBloomFilters();
        signatureCount = 0;
        isLoaded = false;
    }
    
    /**
     * Inner class for database statistics
     */
    public static class DatabaseStats {
        public final long totalSignatures;
        public final long md5Count;
        public final long sha1Count;
        public final long sha256Count;
        public final long bloomFilterCount;
        public final boolean isLoaded;
        
        public DatabaseStats(long total, long md5, long sha1, long sha256, long bloom, boolean loaded) {
            this.totalSignatures = total;
            this.md5Count = md5;
            this.sha1Count = sha1;
            this.sha256Count = sha256;
            this.bloomFilterCount = bloom;
            this.isLoaded = loaded;
        }
    }
}
