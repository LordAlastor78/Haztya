/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.ui;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.haztya.scanner.core.SignatureDatabase;
import com.haztya.scanner.engine.ScanEngine;
import com.haztya.scanner.engine.ScanResult;
import com.haztya.scanner.network.DatabaseDownloader;
import com.haztya.scanner.realtime.RealtimeMonitor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Main activity with improved UI and functionality
 */
public class MainActivity extends AppCompatActivity {
    
    private static final int PERMISSION_REQUEST_CODE = 100;
    
    private SignatureDatabase signatureDatabase;
    private ScanEngine scanEngine;
    private RealtimeMonitor realtimeMonitor;
    private DatabaseDownloader databaseDownloader;
    
    private TextView tvStatus;
    private TextView tvStats;
    private TextView tvLog;
    private ProgressBar progressBar;
    private Button btnQuickScan;
    private Button btnFullScan;
    private Button btnUpdateDb;
    private RecyclerView rvThreatList;
    
    private List<ScanResult> threatResults;
    private ThreatAdapter threatAdapter;
    
    private boolean isScanning = false;
    private boolean realtimeEnabled = false;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // setContentView(R.layout.activity_main); // TODO: Create layout
        
        initializeComponents();
        checkPermissions();
        setupUI();
        loadDatabase();
    }
    
    /**
     * Initialize core components
     */
    private void initializeComponents() {
        signatureDatabase = new SignatureDatabase();
        scanEngine = new ScanEngine(signatureDatabase);
        realtimeMonitor = new RealtimeMonitor(scanEngine);
        databaseDownloader = new DatabaseDownloader(this);
        
        threatResults = new ArrayList<>();
        threatAdapter = new ThreatAdapter(threatResults);
        
        setupListeners();
    }
    
    /**
     * Setup event listeners
     */
    private void setupListeners() {
        // Scan engine listener
        scanEngine.addListener(new ScanEngine.ScanListener() {
            @Override
            public void onScanStarted(int totalFiles) {
                runOnUiThread(() -> {
                    isScanning = true;
                    updateStatus("Scanning " + totalFiles + " files...");
                    progressBar.setVisibility(View.VISIBLE);
                    progressBar.setMax(totalFiles);
                });
            }
            
            @Override
            public void onProgress(int filesScanned, long bytesScanned) {
                runOnUiThread(() -> {
                    progressBar.setProgress(filesScanned);
                    updateStats(filesScanned, scanEngine.getThreatsDetected(), bytesScanned);
                });
            }
            
            @Override
            public void onThreatDetected(ScanResult result) {
                runOnUiThread(() -> {
                    threatResults.add(result);
                    threatAdapter.notifyDataSetChanged();
                    logMessage("⚠️ THREAT: " + result.getFile().getName());
                    
                    if (result.getThreat() != null) {
                        logMessage("   " + result.getThreat().toString());
                    }
                });
            }
            
            @Override
            public void onScanCompleted(int totalFiles, int threatsFound, long duration) {
                runOnUiThread(() -> {
                    isScanning = false;
                    progressBar.setVisibility(View.GONE);
                    updateStatus("Scan completed: " + threatsFound + " threats found");
                    logMessage(String.format("Scan completed in %.2f seconds", duration / 1000.0));
                    
                    if (threatsFound > 0) {
                        showThreatDialog(threatsFound);
                    }
                });
            }
            
            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    logMessage("ERROR: " + error);
                    Toast.makeText(MainActivity.this, error, Toast.LENGTH_SHORT).show();
                });
            }
        });
        
        // Database downloader listener
        databaseDownloader.setListener(new DatabaseDownloader.DownloadListener() {
            @Override
            public void onDownloadStarted(int totalDatabases) {
                runOnUiThread(() -> {
                    updateStatus("Downloading " + totalDatabases + " databases...");
                    progressBar.setVisibility(View.VISIBLE);
                });
            }
            
            @Override
            public void onProgress(String message) {
                runOnUiThread(() -> logMessage(message));
            }
            
            @Override
            public void onDownloadCompleted(int successful, int failed) {
                runOnUiThread(() -> {
                    progressBar.setVisibility(View.GONE);
                    updateStatus("Download completed: " + successful + " successful");
                    
                    if (successful > 0) {
                        loadDatabase();
                    }
                });
            }
            
            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    logMessage("Download error: " + error);
                    Toast.makeText(MainActivity.this, error, Toast.LENGTH_SHORT).show();
                });
            }
        });
        
        // Realtime monitor listener
        realtimeMonitor.setListener(new RealtimeMonitor.RealtimeListener() {
            @Override
            public void onMonitoringStarted(File directory) {
                runOnUiThread(() -> {
                    realtimeEnabled = true;
                    updateStatus("Real-time protection enabled");
                    logMessage("Monitoring: " + directory.getAbsolutePath());
                });
            }
            
            @Override
            public void onMonitoringStopped() {
                runOnUiThread(() -> {
                    realtimeEnabled = false;
                    updateStatus("Real-time protection disabled");
                });
            }
            
            @Override
            public void onThreatDetected(File file, ScanResult result) {
                runOnUiThread(() -> {
                    showThreatNotification(file, result);
                    logMessage("🔴 REALTIME THREAT: " + file.getName());
                });
            }
            
            @Override
            public void onError(String error) {
                runOnUiThread(() -> logMessage("Realtime error: " + error));
            }
        });
    }
    
    /**
     * Setup UI components
     */
    private void setupUI() {
        // TODO: Initialize UI components after creating layout
        // tvStatus = findViewById(R.id.tvStatus);
        // tvStats = findViewById(R.id.tvStats);
        // tvLog = findViewById(R.id.tvLog);
        // progressBar = findViewById(R.id.progressBar);
        // btnQuickScan = findViewById(R.id.btnQuickScan);
        // btnFullScan = findViewById(R.id.btnFullScan);
        // btnUpdateDb = findViewById(R.id.btnUpdateDb);
        // rvThreatList = findViewById(R.id.rvThreatList);
        
        // rvThreatList.setLayoutManager(new LinearLayoutManager(this));
        // rvThreatList.setAdapter(threatAdapter);
    }
    
    /**
     * Check and request permissions
     */
    private void checkPermissions() {
        List<String> permissionsNeeded = new ArrayList<>();
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                permissionsNeeded.add(Manifest.permission.READ_EXTERNAL_STORAGE);
            }
            
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
                if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                        != PackageManager.PERMISSION_GRANTED) {
                    permissionsNeeded.add(Manifest.permission.WRITE_EXTERNAL_STORAGE);
                }
            }
        }
        
        if (!permissionsNeeded.isEmpty()) {
            ActivityCompat.requestPermissions(this, 
                permissionsNeeded.toArray(new String[0]), 
                PERMISSION_REQUEST_CODE);
        }
    }
    
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, 
                                          @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            
            if (!allGranted) {
                Toast.makeText(this, "Storage permissions required", Toast.LENGTH_LONG).show();
            }
        }
    }
    
    /**
     * Load signature database
     */
    private void loadDatabase() {
        File dbDir = new File(getFilesDir(), "databases");
        if (!dbDir.exists()) {
            dbDir.mkdirs();
        }
        
        File mainDb = new File(dbDir, "main.db");
        if (mainDb.exists()) {
            try {
                signatureDatabase.loadFromDisk(mainDb);
                updateStatus("Database loaded: " + signatureDatabase.getSignatureCount() + " signatures");
            } catch (Exception e) {
                logMessage("Error loading database: " + e.getMessage());
            }
        } else {
            updateStatus("Database not found. Please update.");
        }
    }
    
    /**
     * Perform quick scan
     */
    public void onQuickScan(View view) {
        if (isScanning) {
            Toast.makeText(this, "Scan already in progress", Toast.LENGTH_SHORT).show();
            return;
        }
        
        List<File> filesToScan = new ArrayList<>();
        File downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        collectFiles(downloadDir, filesToScan, 1); // 1 level deep
        
        scanEngine.startScan(filesToScan);
    }
    
    /**
     * Perform full scan
     */
    public void onFullScan(View view) {
        if (isScanning) {
            Toast.makeText(this, "Scan already in progress", Toast.LENGTH_SHORT).show();
            return;
        }
        
        List<File> filesToScan = new ArrayList<>();
        File storageDir = Environment.getExternalStorageDirectory();
        collectFiles(storageDir, filesToScan, -1); // Unlimited depth
        
        scanEngine.startScan(filesToScan);
    }
    
    /**
     * Update database
     */
    public void onUpdateDatabase(View view) {
        File dbDir = new File(getFilesDir(), "databases");
        if (!dbDir.exists()) {
            dbDir.mkdirs();
        }
        
        databaseDownloader.downloadDatabases(dbDir);
    }
    
    /**
     * Toggle realtime protection
     */
    public void toggleRealtimeProtection(MenuItem item) {
        if (realtimeEnabled) {
            realtimeMonitor.stopMonitoring();
        } else {
            File storageDir = Environment.getExternalStorageDirectory();
            realtimeMonitor.startMonitoring(storageDir);
        }
    }
    
    /**
     * Collect files recursively
     */
    private void collectFiles(File dir, List<File> fileList, int maxDepth) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) return;
        if (maxDepth == 0) return;
        
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    fileList.add(file);
                } else if (file.isDirectory() && maxDepth != 0) {
                    collectFiles(file, fileList, maxDepth > 0 ? maxDepth - 1 : -1);
                }
            }
        }
    }
    
    // UI update methods
    private void updateStatus(String status) {
        if (tvStatus != null) {
            tvStatus.setText(status);
        }
    }
    
    private void updateStats(int filesScanned, int threats, long bytes) {
        if (tvStats != null) {
            String stats = String.format("Files: %d | Threats: %d | Data: %s",
                filesScanned, threats, formatBytes(bytes));
            tvStats.setText(stats);
        }
    }
    
    private void logMessage(String message) {
        if (tvLog != null) {
            tvLog.append(message + "\n");
        }
    }
    
    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.2f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }
    
    private void showThreatDialog(int threatCount) {
        // TODO: Show alert dialog with threat details
    }
    
    private void showThreatNotification(File file, ScanResult result) {
        // TODO: Show system notification for realtime threat
    }
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (realtimeEnabled) {
            realtimeMonitor.stopMonitoring();
        }
    }
    
    /**
     * Threat adapter for RecyclerView
     */
    private static class ThreatAdapter extends RecyclerView.Adapter<ThreatAdapter.ThreatViewHolder> {
        private final List<ScanResult> threats;
        
        ThreatAdapter(List<ScanResult> threats) {
            this.threats = threats;
        }
        
        @NonNull
        @Override
        public ThreatViewHolder onCreateViewHolder(@NonNull android.view.ViewGroup parent, int viewType) {
            // TODO: Inflate threat item layout
            return null;
        }
        
        @Override
        public void onBindViewHolder(@NonNull ThreatViewHolder holder, int position) {
            // TODO: Bind threat data to view
        }
        
        @Override
        public int getItemCount() {
            return threats.size();
        }
        
        static class ThreatViewHolder extends RecyclerView.ViewHolder {
            ThreatViewHolder(@NonNull View itemView) {
                super(itemView);
            }
        }
    }
}
