package com.haztya.scanner;

import com.haztya.clamav.ClamAVScanner;
import com.haztya.detection.HashBasedScanner;
import com.haztya.model.ScanResult;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Composite scanner that uses multiple detection engines
 */
public class CompositeScanner implements MalwareScanner {
    private List<MalwareScanner> scanners;
    
    public CompositeScanner() {
        this.scanners = new ArrayList<>();
        
        // Add hash-based scanner (always available)
        scanners.add(new HashBasedScanner());
        
        // Add ClamAV scanner if available
        ClamAVScanner clamAV = new ClamAVScanner();
        if (clamAV.isAvailable()) {
            scanners.add(clamAV);
        }
    }
    
    /**
     * Add a custom scanner
     * @param scanner Scanner to add
     */
    public void addScanner(MalwareScanner scanner) {
        if (scanner.isAvailable()) {
            scanners.add(scanner);
        }
    }
    
    @Override
    public ScanResult scanFile(File file) throws IOException {
        ScanResult compositeResult = new ScanResult(file.getAbsolutePath());
        compositeResult.setFileSize(file.length());
        compositeResult.setScanEngine(getEngineName());
        
        // Run all available scanners
        for (MalwareScanner scanner : scanners) {
            try {
                ScanResult result = scanner.scanFile(file);
                
                // Collect threats from each scanner
                if (result.isInfected()) {
                    for (String threat : result.getThreats()) {
                        compositeResult.addThreat(threat);
                    }
                }
                
                // Use hash from first scanner that provides it
                if (compositeResult.getFileHash() == null && result.getFileHash() != null) {
                    compositeResult.setFileHash(result.getFileHash());
                }
            } catch (IOException e) {
                System.err.println("Scanner " + scanner.getEngineName() + " failed: " + e.getMessage());
            }
        }
        
        return compositeResult;
    }
    
    @Override
    public String getEngineName() {
        StringBuilder sb = new StringBuilder("Composite Scanner (");
        for (int i = 0; i < scanners.size(); i++) {
            sb.append(scanners.get(i).getEngineName());
            if (i < scanners.size() - 1) {
                sb.append(", ");
            }
        }
        sb.append(")");
        return sb.toString();
    }
    
    @Override
    public boolean isAvailable() {
        return !scanners.isEmpty();
    }
    
    /**
     * Get the list of active scanners
     * @return List of scanner names
     */
    public List<String> getActiveScanners() {
        List<String> names = new ArrayList<>();
        for (MalwareScanner scanner : scanners) {
            names.add(scanner.getEngineName());
        }
        return names;
    }
}
