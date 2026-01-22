package com.haztya.util;

import org.apache.commons.codec.digest.DigestUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Utility class for calculating file hashes
 */
public class HashUtil {
    
    /**
     * Calculate MD5 hash of a file
     * @param file The file to hash
     * @return MD5 hash as hex string
     * @throws IOException If file cannot be read
     */
    public static String md5(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return DigestUtils.md5Hex(fis);
        }
    }
    
    /**
     * Calculate SHA-256 hash of a file
     * @param file The file to hash
     * @return SHA-256 hash as hex string
     * @throws IOException If file cannot be read
     */
    public static String sha256(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return DigestUtils.sha256Hex(fis);
        }
    }
    
    /**
     * Calculate SHA-1 hash of a file
     * @param file The file to hash
     * @return SHA-1 hash as hex string
     * @throws IOException If file cannot be read
     */
    public static String sha1(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return DigestUtils.sha1Hex(fis);
        }
    }
}
