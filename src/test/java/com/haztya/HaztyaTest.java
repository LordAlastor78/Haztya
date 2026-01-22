package com.haztya;

import com.haztya.model.ScanResult;
import com.haztya.scanner.CompositeScanner;
import com.haztya.util.HashUtil;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.*;

/**
 * Unit tests for Haztya scanner
 */
public class HaztyaTest {
    
    @Test
    public void testScanResult() {
        ScanResult result = new ScanResult("/test/file.txt");
        assertFalse(result.isInfected());
        assertEquals(0, result.getThreats().size());
        
        result.addThreat("Test threat");
        assertTrue(result.isInfected());
        assertEquals(1, result.getThreats().size());
    }
    
    @Test
    public void testHashUtil() throws IOException {
        File tempFile = File.createTempFile("haztya-test", ".txt");
        tempFile.deleteOnExit();
        
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write("Test content for hashing");
        }
        
        String md5 = HashUtil.md5(tempFile);
        assertNotNull(md5);
        assertEquals(32, md5.length()); // MD5 is 32 hex chars
        
        String sha256 = HashUtil.sha256(tempFile);
        assertNotNull(sha256);
        assertEquals(64, sha256.length()); // SHA-256 is 64 hex chars
        
        String sha1 = HashUtil.sha1(tempFile);
        assertNotNull(sha1);
        assertEquals(40, sha1.length()); // SHA-1 is 40 hex chars
    }
    
    @Test
    public void testCompositeScanner() throws IOException {
        CompositeScanner scanner = new CompositeScanner();
        assertTrue(scanner.isAvailable());
        assertFalse(scanner.getActiveScanners().isEmpty());
        
        File tempFile = File.createTempFile("haztya-test", ".txt");
        tempFile.deleteOnExit();
        
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write("Clean test file");
        }
        
        ScanResult result = scanner.scanFile(tempFile);
        assertNotNull(result);
        assertEquals(tempFile.getAbsolutePath(), result.getFilePath());
        assertNotNull(result.getFileHash());
    }
    
    @Test
    public void testEICARDetection() throws IOException {
        // Test with EICAR test file content
        File tempFile = File.createTempFile("eicar-test", ".txt");
        tempFile.deleteOnExit();
        
        // Write EICAR test string
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        }
        
        CompositeScanner scanner = new CompositeScanner();
        ScanResult result = scanner.scanFile(tempFile);
        
        assertNotNull(result);
        // The EICAR file should be detected by hash-based scanner
        assertTrue("EICAR test file should be detected", result.isInfected());
    }
}
