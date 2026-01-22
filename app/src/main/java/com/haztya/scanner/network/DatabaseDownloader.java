/*
 * Haztya: Advanced Malware Scanner for Android
 * Copyright (c) 2026 Haztya Development Team
 * 
 * Licensed under GNU Affero General Public License v3.0
 * See LICENSE file for details
 */
package com.haztya.scanner.network;

import android.content.Context;
import android.os.AsyncTask;

import com.haztya.scanner.core.SignatureDatabase;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Database downloader and updater
 * Downloads signature databases from remote servers
 */
public class DatabaseDownloader {
    
    private final Context context;
    private final List<DatabaseSource> sources;
    private DownloadListener listener;
    
    private boolean isDownloading = false;
    
    private static final int BUFFER_SIZE = 8192;
    private static final int CONNECTION_TIMEOUT = 30000; // 30 seconds
    private static final int READ_TIMEOUT = 30000;
    
    public DatabaseDownloader(Context context) {
        this.context = context;
        this.sources = new ArrayList<>();
        initializeSources();
    }
    
    /**
     * Initialize database sources
     */
    private void initializeSources() {
        // Add default sources
        sources.add(new DatabaseSource(
            "Haztya Main Database",
            "https://signatures.haztya.com/main.bloom",
            "main",
            DatabaseType.BLOOM_FILTER
        ));
        
        sources.add(new DatabaseSource(
            "Extended Signatures",
            "https://signatures.haztya.com/extended.bloom",
            "extended",
            DatabaseType.BLOOM_FILTER
        ));
        
        sources.add(new DatabaseSource(
            "Malicious Domains",
            "https://signatures.haztya.com/domains.bloom",
            "domains",
            DatabaseType.DOMAIN_LIST
        ));
    }
    
    /**
     * Download all databases
     */
    public void downloadDatabases(File targetDirectory) {
        if (isDownloading) {
            notifyError("Download already in progress");
            return;
        }
        
        isDownloading = true;
        notifyDownloadStarted(sources.size());
        
        new DownloadTask(targetDirectory).execute(sources);
    }
    
    /**
     * Download a single database
     */
    private boolean downloadDatabase(DatabaseSource source, File targetDirectory) {
        File outputFile = new File(targetDirectory, source.getName() + ".db");
        
        try {
            URL url = new URL(source.getUrl());
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(READ_TIMEOUT);
            connection.setInstanceFollowRedirects(true);
            
            // Check if file exists and get ETag/Last-Modified
            if (outputFile.exists()) {
                String etag = getStoredETag(outputFile);
                if (etag != null) {
                    connection.setRequestProperty("If-None-Match", etag);
                }
            }
            
            int responseCode = connection.getResponseCode();
            
            // 304 Not Modified - file hasn't changed
            if (responseCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                notifyProgress(source.getName() + " (not modified)");
                return true;
            }
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                long fileSize = connection.getContentLengthLong();
                
                try (InputStream is = connection.getInputStream();
                     FileOutputStream fos = new FileOutputStream(outputFile)) {
                    
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    long totalRead = 0;
                    
                    while ((bytesRead = is.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                        totalRead += bytesRead;
                        
                        if (fileSize > 0) {
                            int progress = (int) ((totalRead * 100) / fileSize);
                            notifyProgress(source.getName() + ": " + progress + "%");
                        }
                    }
                }
                
                // Store ETag for future checks
                String etag = connection.getHeaderField("ETag");
                if (etag != null) {
                    storeETag(outputFile, etag);
                }
                
                notifyProgress(source.getName() + " downloaded successfully");
                return true;
            }
            
        } catch (Exception e) {
            notifyError("Failed to download " + source.getName() + ": " + e.getMessage());
            return false;
        }
        
        return false;
    }
    
    /**
     * Verify downloaded database integrity
     */
    private boolean verifyDatabaseIntegrity(File databaseFile, String expectedHash) {
        if (expectedHash == null || expectedHash.isEmpty()) {
            return true; // No hash to verify
        }
        
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream is = new java.io.FileInputStream(databaseFile)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    md.update(buffer, 0, bytesRead);
                }
            }
            
            byte[] digest = md.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b));
            }
            
            return hexString.toString().equalsIgnoreCase(expectedHash);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get stored ETag for file
     */
    private String getStoredETag(File file) {
        // TODO: Implement ETag storage (SharedPreferences or file)
        return null;
    }
    
    /**
     * Store ETag for file
     */
    private void storeETag(File file, String etag) {
        // TODO: Implement ETag storage
    }
    
    /**
     * Add custom database source
     */
    public void addSource(DatabaseSource source) {
        sources.add(source);
    }
    
    /**
     * Set download listener
     */
    public void setListener(DownloadListener listener) {
        this.listener = listener;
    }
    
    // Notification methods
    private void notifyDownloadStarted(int totalDatabases) {
        if (listener != null) {
            listener.onDownloadStarted(totalDatabases);
        }
    }
    
    private void notifyProgress(String message) {
        if (listener != null) {
            listener.onProgress(message);
        }
    }
    
    private void notifyDownloadCompleted(int successful, int failed) {
        isDownloading = false;
        if (listener != null) {
            listener.onDownloadCompleted(successful, failed);
        }
    }
    
    private void notifyError(String error) {
        if (listener != null) {
            listener.onError(error);
        }
    }
    
    /**
     * AsyncTask for downloading databases
     */
    private class DownloadTask extends AsyncTask<List<DatabaseSource>, String, Integer> {
        private final File targetDirectory;
        private int failedDownloads = 0;
        
        DownloadTask(File targetDirectory) {
            this.targetDirectory = targetDirectory;
        }
        
        @Override
        protected Integer doInBackground(List<DatabaseSource>... lists) {
            List<DatabaseSource> sources = lists[0];
            int successful = 0;
            
            for (DatabaseSource source : sources) {
                if (downloadDatabase(source, targetDirectory)) {
                    successful++;
                } else {
                    failedDownloads++;
                }
            }
            
            return successful;
        }
        
        @Override
        protected void onPostExecute(Integer successful) {
            notifyDownloadCompleted(successful, failedDownloads);
        }
    }
    
    /**
     * Database source information
     */
    public static class DatabaseSource {
        private final String displayName;
        private final String url;
        private final String name;
        private final DatabaseType type;
        private String expectedHash;
        
        public DatabaseSource(String displayName, String url, String name, DatabaseType type) {
            this.displayName = displayName;
            this.url = url;
            this.name = name;
            this.type = type;
        }
        
        public String getDisplayName() { return displayName; }
        public String getUrl() { return url; }
        public String getName() { return name; }
        public DatabaseType getType() { return type; }
        public String getExpectedHash() { return expectedHash; }
        
        public void setExpectedHash(String hash) { this.expectedHash = hash; }
    }
    
    /**
     * Database types
     */
    public enum DatabaseType {
        BLOOM_FILTER,
        HASH_LIST,
        DOMAIN_LIST,
        YARA_RULES
    }
    
    /**
     * Download listener interface
     */
    public interface DownloadListener {
        void onDownloadStarted(int totalDatabases);
        void onProgress(String message);
        void onDownloadCompleted(int successful, int failed);
        void onError(String error);
    }
}
