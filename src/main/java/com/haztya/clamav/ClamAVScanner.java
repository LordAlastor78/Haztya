package com.haztya.clamav;

import com.haztya.model.ScanResult;
import com.haztya.scanner.MalwareScanner;
import com.haztya.util.HashUtil;

import java.io.*;

/**
 * ClamAV-based malware scanner
 * Communicates with ClamAV daemon (clamd) via socket
 */
public class ClamAVScanner implements MalwareScanner {
    private String clamHost;
    private int clamPort;
    private int timeout;
    
    public ClamAVScanner() {
        this("localhost", 3310, 10000);
    }
    
    public ClamAVScanner(String host, int port, int timeout) {
        this.clamHost = host;
        this.clamPort = port;
        this.timeout = timeout;
    }
    
    @Override
    public ScanResult scanFile(File file) throws IOException {
        ScanResult result = new ScanResult(file.getAbsolutePath());
        result.setFileSize(file.length());
        result.setScanEngine(getEngineName());
        
        // Calculate file hash
        try {
            result.setFileHash(HashUtil.sha256(file));
        } catch (IOException e) {
            System.err.println("Warning: Could not calculate file hash: " + e.getMessage());
        }
        
        // Check if ClamAV is available
        if (!isAvailable()) {
            System.err.println("Warning: ClamAV is not available. Skipping ClamAV scan.");
            return result;
        }
        
        // Scan with ClamAV
        try {
            String scanResult = scanWithClamAV(file);
            if (scanResult != null && !scanResult.contains("OK")) {
                result.addThreat("ClamAV: " + scanResult);
            }
        } catch (Exception e) {
            System.err.println("ClamAV scan error: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Scan a file using ClamAV daemon
     * @param file File to scan
     * @return Scan result string
     */
    private String scanWithClamAV(File file) throws IOException {
        // This is a simplified implementation
        // In a real implementation, this would connect to clamd via socket
        // and send the file for scanning
        
        // Try to execute clamdscan command if available
        try {
            ProcessBuilder pb = new ProcessBuilder("clamdscan", "--no-summary", file.getAbsolutePath());
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }
            
            int exitCode = process.waitFor();
            if (exitCode == 1) {
                // Virus found
                return output.toString();
            } else if (exitCode == 0) {
                // Clean
                return "OK";
            }
            return output.toString();
        } catch (Exception e) {
            throw new IOException("ClamAV scan failed: " + e.getMessage());
        }
    }
    
    @Override
    public String getEngineName() {
        return "ClamAV";
    }
    
    @Override
    public boolean isAvailable() {
        // Check if clamdscan or clamscan is available
        try {
            ProcessBuilder pb = new ProcessBuilder("which", "clamdscan");
            Process process = pb.start();
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                return true;
            }
            
            // Try clamscan as fallback
            pb = new ProcessBuilder("which", "clamscan");
            process = pb.start();
            exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
