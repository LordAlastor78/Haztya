package com.haztya.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Represents the result of a malware scan
 */
public class ScanResult {
    private String filePath;
    private boolean infected;
    private List<String> threats;
    private String fileHash;
    private long fileSize;
    private Date scanDate;
    private String scanEngine;

    public ScanResult(String filePath) {
        this.filePath = filePath;
        this.infected = false;
        this.threats = new ArrayList<>();
        this.scanDate = new Date();
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public boolean isInfected() {
        return infected;
    }

    public void setInfected(boolean infected) {
        this.infected = infected;
    }

    public List<String> getThreats() {
        return threats;
    }

    public void addThreat(String threat) {
        this.threats.add(threat);
        this.infected = true;
    }

    public String getFileHash() {
        return fileHash;
    }

    public void setFileHash(String fileHash) {
        this.fileHash = fileHash;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public Date getScanDate() {
        return scanDate;
    }

    public void setScanDate(Date scanDate) {
        this.scanDate = scanDate;
    }

    public String getScanEngine() {
        return scanEngine;
    }

    public void setScanEngine(String scanEngine) {
        this.scanEngine = scanEngine;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("File: ").append(filePath).append("\n");
        sb.append("Status: ").append(infected ? "INFECTED" : "CLEAN").append("\n");
        if (infected && !threats.isEmpty()) {
            sb.append("Threats: ").append(String.join(", ", threats)).append("\n");
        }
        if (fileHash != null) {
            sb.append("Hash: ").append(fileHash).append("\n");
        }
        sb.append("Size: ").append(fileSize).append(" bytes\n");
        sb.append("Scan Date: ").append(scanDate).append("\n");
        if (scanEngine != null) {
            sb.append("Engine: ").append(scanEngine).append("\n");
        }
        return sb.toString();
    }
}
