package com.haztya;

import com.haztya.model.ScanResult;
import com.haztya.scanner.CompositeScanner;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Haztya - Open-source anti-malware scanner
 * Main application class
 */
public class Haztya {
    
    private static final String VERSION = "1.0.0";
    
    public static void main(String[] args) {
        System.out.println("╔═══════════════════════════════════════════╗");
        System.out.println("║     Haztya Anti-Malware Scanner v" + VERSION + "     ║");
        System.out.println("║  Based on ClamAV & Malware Databases  ║");
        System.out.println("╚═══════════════════════════════════════════╝");
        System.out.println();
        
        if (args.length == 0) {
            printUsage();
            return;
        }
        
        String command = args[0];
        
        switch (command) {
            case "scan":
                if (args.length < 2) {
                    System.err.println("Error: No file or directory specified");
                    printUsage();
                    System.exit(1);
                }
                scanFiles(args[1]);
                break;
                
            case "info":
                printInfo();
                break;
                
            case "version":
                printVersion();
                break;
                
            case "help":
                printUsage();
                break;
                
            default:
                System.err.println("Unknown command: " + command);
                printUsage();
                System.exit(1);
        }
    }
    
    private static void scanFiles(String path) {
        File target = new File(path);
        
        if (!target.exists()) {
            System.err.println("Error: File or directory not found: " + path);
            System.exit(1);
        }
        
        CompositeScanner scanner = new CompositeScanner();
        
        System.out.println("Active scanners: " + String.join(", ", scanner.getActiveScanners()));
        System.out.println();
        
        List<File> filesToScan = new ArrayList<>();
        
        if (target.isDirectory()) {
            System.out.println("Scanning directory: " + target.getAbsolutePath());
            collectFiles(target, filesToScan);
        } else {
            filesToScan.add(target);
        }
        
        System.out.println("Found " + filesToScan.size() + " file(s) to scan");
        System.out.println("─────────────────────────────────────────────");
        System.out.println();
        
        int cleanCount = 0;
        int infectedCount = 0;
        int errorCount = 0;
        
        for (File file : filesToScan) {
            try {
                System.out.println("Scanning: " + file.getAbsolutePath());
                ScanResult result = scanner.scanFile(file);
                
                if (result.isInfected()) {
                    System.out.println("  ⚠ STATUS: INFECTED");
                    System.out.println("  Threats detected:");
                    for (String threat : result.getThreats()) {
                        System.out.println("    - " + threat);
                    }
                    infectedCount++;
                } else {
                    System.out.println("  ✓ STATUS: CLEAN");
                    cleanCount++;
                }
                
                if (result.getFileHash() != null) {
                    System.out.println("  Hash: " + result.getFileHash());
                }
                System.out.println();
                
            } catch (IOException e) {
                System.err.println("  ✗ ERROR: " + e.getMessage());
                errorCount++;
                System.out.println();
            }
        }
        
        System.out.println("─────────────────────────────────────────────");
        System.out.println("SCAN SUMMARY");
        System.out.println("  Total files scanned: " + filesToScan.size());
        System.out.println("  Clean files: " + cleanCount);
        System.out.println("  Infected files: " + infectedCount);
        System.out.println("  Errors: " + errorCount);
        System.out.println();
        
        if (infectedCount > 0) {
            System.out.println("⚠ WARNING: Infected files detected!");
            System.exit(1);
        } else {
            System.out.println("✓ All files are clean");
        }
    }
    
    private static void collectFiles(File directory, List<File> files) {
        File[] entries = directory.listFiles();
        if (entries != null) {
            for (File entry : entries) {
                if (entry.isDirectory()) {
                    collectFiles(entry, files);
                } else {
                    files.add(entry);
                }
            }
        }
    }
    
    private static void printInfo() {
        CompositeScanner scanner = new CompositeScanner();
        
        System.out.println("Haztya Information");
        System.out.println("──────────────────");
        System.out.println("Version: " + VERSION);
        System.out.println("Active Scanners: " + scanner.getActiveScanners().size());
        for (String scannerName : scanner.getActiveScanners()) {
            System.out.println("  - " + scannerName);
        }
        System.out.println();
        System.out.println("Features:");
        System.out.println("  - ClamAV integration");
        System.out.println("  - Hash-based detection (MD5, SHA-256)");
        System.out.println("  - Directory scanning");
        System.out.println("  - Multi-engine scanning");
        System.out.println();
    }
    
    private static void printVersion() {
        System.out.println("Haztya version " + VERSION);
    }
    
    private static void printUsage() {
        System.out.println("Usage: java -jar haztya.jar <command> [options]");
        System.out.println();
        System.out.println("Commands:");
        System.out.println("  scan <path>    Scan a file or directory for malware");
        System.out.println("  info           Display scanner information");
        System.out.println("  version        Display version information");
        System.out.println("  help           Display this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar haztya.jar scan /path/to/file");
        System.out.println("  java -jar haztya.jar scan /path/to/directory");
        System.out.println("  java -jar haztya.jar info");
        System.out.println();
    }
}
