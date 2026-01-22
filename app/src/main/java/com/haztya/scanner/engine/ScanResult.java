/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.engine;

import com.haztya.scanner.core.MalwareSignature;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents the result of a file scan
 */
public class ScanResult {
    
    private final File file;
    private Status status;
    private MalwareSignature threat;
    private String detectionMethod;
    private int heuristicScore;
    private List<String> suspicionIndicators;
    private String errorMessage;
    private long scanDuration;
    
    public enum Status {
        CLEAN,
        THREAT_DETECTED,
        SUSPICIOUS,
        ERROR,
        SKIPPED
    }
    
    public ScanResult(File file) {
        this.file = file;
        this.status = Status.CLEAN;
        this.suspicionIndicators = new ArrayList<>();
        this.heuristicScore = 0;
    }
    
    public ScanResult(File file, Status status, String message) {
        this.file = file;
        this.status = status;
        this.errorMessage = message;
        this.suspicionIndicators = new ArrayList<>();
    }
    
    // Getters and Setters
    public File getFile() { return file; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    
    public MalwareSignature getThreat() { return threat; }
    public void setThreat(MalwareSignature threat) { this.threat = threat; }
    
    public String getDetectionMethod() { return detectionMethod; }
    public void setDetectionMethod(String method) { this.detectionMethod = method; }
    
    public int getHeuristicScore() { return heuristicScore; }
    public void setHeuristicScore(int score) { this.heuristicScore = score; }
    
    public List<String> getSuspicionIndicators() { return suspicionIndicators; }
    public void setSuspicionIndicators(List<String> indicators) { 
        this.suspicionIndicators = indicators; 
    }
    
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String message) { this.errorMessage = message; }
    
    public long getScanDuration() { return scanDuration; }
    public void setScanDuration(long duration) { this.scanDuration = duration; }
    
    public boolean isThreat() {
        return status == Status.THREAT_DETECTED || status == Status.SUSPICIOUS;
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("File: ").append(file.getName()).append("\n");
        sb.append("Status: ").append(status).append("\n");
        
        if (threat != null) {
            sb.append("Threat: ").append(threat.getMalwareName()).append("\n");
            sb.append("Family: ").append(threat.getMalwareFamily()).append("\n");
            sb.append("Level: ").append(threat.getThreatLevel()).append("\n");
        }
        
        if (heuristicScore > 0) {
            sb.append("Heuristic Score: ").append(heuristicScore).append("\n");
        }
        
        if (!suspicionIndicators.isEmpty()) {
            sb.append("Indicators:\n");
            for (String indicator : suspicionIndicators) {
                sb.append("  - ").append(indicator).append("\n");
            }
        }
        
        return sb.toString();
    }
}
