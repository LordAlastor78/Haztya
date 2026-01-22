package com.haztya.detection;

import com.haztya.model.ScanResult;
import com.haztya.scanner.MalwareScanner;
import com.haztya.util.HashUtil;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * Hash-based malware detection using known malware signatures
 */
public class HashBasedScanner implements MalwareScanner {
    private Set<String> knownMalwareHashes;
    
    public HashBasedScanner() {
        this.knownMalwareHashes = new HashSet<>();
        loadKnownMalwareHashes();
    }
    
    /**
     * Load known malware hashes from database
     */
    private void loadKnownMalwareHashes() {
        // In a real implementation, this would load from a database file
        // For now, we'll use a small example set
        
        // EICAR test file hashes (standard anti-virus test file)
        knownMalwareHashes.add("44d88612fea8a8f36de82e1278abb02f"); // EICAR test file MD5
        knownMalwareHashes.add("69630e4574ec6798239b091cda43dca0"); // EICAR with newline MD5
        knownMalwareHashes.add("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"); // EICAR SHA-256
        knownMalwareHashes.add("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267"); // EICAR with newline SHA-256
    }
    
    /**
     * Add a malware hash to the database
     * @param hash Hash to add
     */
    public void addMalwareHash(String hash) {
        knownMalwareHashes.add(hash.toLowerCase());
    }
    
    @Override
    public ScanResult scanFile(File file) throws IOException {
        ScanResult result = new ScanResult(file.getAbsolutePath());
        result.setFileSize(file.length());
        result.setScanEngine(getEngineName());
        
        // Calculate hashes
        String md5 = HashUtil.md5(file);
        String sha256 = HashUtil.sha256(file);
        result.setFileHash(sha256);
        
        // Check against known malware hashes
        if (knownMalwareHashes.contains(md5.toLowerCase())) {
            result.addThreat("Known malware (MD5 match): " + md5);
        }
        
        if (knownMalwareHashes.contains(sha256.toLowerCase())) {
            result.addThreat("Known malware (SHA-256 match): " + sha256);
        }
        
        return result;
    }
    
    @Override
    public String getEngineName() {
        return "Hash-Based Detection";
    }
    
    @Override
    public boolean isAvailable() {
        return true;
    }
    
    /**
     * Get the number of known malware hashes
     * @return Count of malware hashes
     */
    public int getMalwareHashCount() {
        return knownMalwareHashes.size();
    }
}
