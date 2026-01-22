# Haztya - Advanced Malware Scanner for Android

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Java](https://img.shields.io/badge/Java-17-orange.svg)
![Android](https://img.shields.io/badge/Android-7.0%2B-green.svg)
![License](https://img.shields.io/badge/license-AGPL--3.0-red.svg)

## 🛡️ Overview

**Haztya** is an open-source advanced malware scanner for Android, built from scratch to be faster, leaner, and more powerful than Hypatia. It ships multi-layer detection, heuristic analysis, and real-time protection.

### Key Features

#### 🚀 Performance Tuned
- **Advanced multithreading**: Efficiently uses all CPU cores
- **Single-pass hashing**: MD5, SHA-1, SHA-256, and SHA-512 in one read
- **Smart cache**: Skips files already verified
- **Battery friendly**: Designed to minimize drain

#### 🔍 Multi-Layer Detection
1. **Signature-based detection**: BloomFilters for ultra-fast O(k) lookups
2. **Heuristic analysis** for unknown threats via:
   - Entropy scoring (packed/encrypted file detection)
   - Suspicious extension checks
   - Double-extension detection
   - Size anomaly detection
3. **APK analysis**: Android app inspection
4. **Fuzzy hashing**: Variant detection

#### 🛡️ Real-Time Protection
- Recursive filesystem monitoring
- Auto-scan on new/modified files
- Configurable cooldown to avoid repeated scans
- Instant threat notifications

#### 📊 Advanced Threat Database
- **Multiple data structures**:
  - BloomFilters for fast lookups (0.1% false-positive target)
  - HashMaps for exact matches
  - YARA pattern support
- **Rich threat metadata**:
  - Malware name
  - Family
  - Severity (LOW, MEDIUM, HIGH, CRITICAL)
  - Signature source (ClamAV, ESET, etc.)
  - Description
- **Efficient updates**: HTTP ETags to download only deltas

## 📋 System Requirements

- **Android**: 7.0 (Nougat) or newer
- **RAM**: 2GB minimum (4GB recommended for full scans)
- **Storage**: 500MB for app and databases

## 🏗️ Project Architecture

```
com.haztya.scanner/
├── core/                       # Core components
│   ├── HashCalculator.java     # Optimized hash calculation
│   ├── SignatureDatabase.java  # Database management
│   └── MalwareSignature.java   # Signature data model
│
├── engine/                     # Scan engine
│   ├── ScanEngine.java         # Multithreaded scan engine
│   └── ScanResult.java         # Scan results
│
├── realtime/                   # Real-time protection
│   └── RealtimeMonitor.java    # Recursive file monitor
│
├── network/                    # Networking helpers
│   └── DatabaseDownloader.java # Database downloads
│
└── ui/                         # User interface
    └── MainActivity.java       # Main activity
```

## 🔧 Technologies & Libraries

### Core Dependencies
- **AndroidX**: Modern Android components (AppCompat, RecyclerView, Room)
- **Guava 33.0.0**: BloomFilters and advanced data structures
- **BouncyCastle 1.77**: Crypto and signature validation
- **Apache Commons**: IO, compression, and collections utilities
- **OkHttp 4.12**: Efficient HTTP client
- **Room Database**: Local persistence for scan history

### Implemented Algorithms
- **Hashing**: MD5, SHA-1, SHA-256, SHA-512 (single pass)
- **Fuzzy hashing**: ssdeep-style variant detection
- **Shannon entropy**: Packed/encrypted file detection
- **BloomFilter**: Probabilistic O(k) lookups

## 📊 Hypatia Comparison

| Feature | Hypatia | Haztya |
|---------|---------|---------|
| Hash algorithms | MD5, SHA-1, SHA-256 | MD5, SHA-1, SHA-256, SHA-512, Fuzzy |
| Heuristic analysis | No | ✅ Yes (multiple indicators) |
| Hash computation | 3 passes | **1 pass** (optimized) |
| Threading | Basic | Advanced (adaptive pool) |
| Data structures | BloomFilter only | BloomFilter + HashMap + YARA |
| Threat metadata | Limited | Detailed (family, level, source) |
| Entropy analysis | No | ✅ Yes |
| Variant detection | No | ✅ Yes (fuzzy hashing) |
| Java version | 8 | **17** |
| Min Android API | 16 (Android 4.1) | 24 (Android 7.0) |
| Target SDK | 32 | **34** |
| Architecture | Monolithic | **Modular** |
| Room Database | No | ✅ Yes |
| Material Design 3 | No | ✅ Yes |
| Gradle version | 7.2 | **8.2** |

## 🚀 Build & Install

### Prerequisites
```bash
- JDK 17 or newer
- Android SDK (API 34)
- Gradle 8.2+
```

### Steps
```bash
# 1. Clone the repository
git clone https://github.com/tuusuario/Haztya.git
cd Haztya

# 2. Build the project
./gradlew assembleRelease

# 3. Install on a device
adb install app/build/outputs/apk/release/app-release.apk
```

## 📱 Usage

### Quick Scan
Scans common directories (Downloads, recent documents).

### Full Scan
Scans the entire device storage.

### Real-Time Protection
Enables continuous filesystem monitoring.

### Update Database
Downloads the latest malware signatures from remote servers.

## 🎯 Technical Optimizations

### 1. Single-Pass Multi-Algorithm Hashing
```java
// Hypatia: 3 file reads
String md5 = calculateMD5(file);      // Read 1
String sha1 = calculateSHA1(file);    // Read 2
String sha256 = calculateSHA256(file); // Read 3

// Haztya: 1 read for all hashes
ConcurrentHashMap<HashType, String> hashes = HashCalculator.calculateAllHashes(file);
```

### 2. BloomFilter with Low False Positives
```java
BloomFilter<String> filter = BloomFilter.create(
    Funnels.stringFunnel(UTF_8),
    10_000_000,  // 10 million signatures
    0.001        // 0.1% false positives
);
```

### 3. Adaptive Thread Pool
```java
// Adapts to available CPU cores
int threadCount = Runtime.getRuntime().availableProcessors();
ExecutorService executor = Executors.newFixedThreadPool(threadCount);
```

### 4. Recent Scan Cache
```java
// Skips rescanning the same file repeatedly
ConcurrentHashMap<String, Long> recentScans = new ConcurrentHashMap<>();
if (currentTime - lastScan < COOLDOWN_MS) return; // Skip
```

## 📈 Expected Performance

| Metric | Hypatia | Haztya |
|--------|---------|---------|
| 1MB file scan | ~20ms | **< 15ms** |
| 40MB file scan | ~1000ms | **< 800ms** |
| Memory (DB loaded) | ~120MB | **< 150MB** |
| Battery (realtime 24h) | ~3% | **< 2%** |
| Throughput | ~30 files/sec | **~50 files/sec** |

## 🛣️ Roadmap

### v1.1 (Upcoming)
- [ ] Full YARA rule support
- [ ] Advanced APK permission analysis
- [ ] Machine learning for heuristics
- [ ] Export reports to PDF/JSON

### v1.2 (Future)
- [ ] Infected file quarantine
- [ ] Scheduled automatic scans
- [ ] Status widget on home screen
- [ ] Root mode for full system scans

### v2.0 (Long-term)
- [ ] Runtime behavior analysis
- [ ] Ransomware-specific detection
- [ ] Network traffic analysis
- [ ] Web portal for remote management

## 🔒 Privacy & Security

- ✅ **100% offline**: Files never leave the device
- ✅ **No tracking**: We do not collect user data
- ✅ **Open source**: Fully auditable
- ✅ **Ad-free**: Free software with no ads
- ✅ **AGPL-3.0 license**: Freedom preserved

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 - see [LICENSE](LICENSE) for details.

```
Haztya: Advanced Malware Scanner for Android
Copyright (c) 2026 Haztya Development Team

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

## 🙏 Acknowledgements

- **Hypatia** for inspiration and the conceptual base
- **ClamAV** for signature databases (GPLv2)
- **ESET** for additional databases (BSD 2-Clause)
- **MalwareBazaar** for malware signatures (CC0)
- **Open-source community** for the libraries used

## 🤝 Contributing

Contributions are welcome! Areas of interest:
- 🐛 Bug reports
- 💡 Feature suggestions
- 📝 Documentation improvements
- 🌍 New translations
- 🔒 Security audits

---

**Made with ❤️ by the Haztya Team**

**Based on Hypatia — reimplemented and optimized from scratch**


