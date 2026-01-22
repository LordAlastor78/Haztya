# Haztya

![Java](https://img.shields.io/badge/Java-11+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

A Open-source anti-malware tool scanner based on ClamAV and other databases of malware. Built with Java, Haztya provides clean, secure malware scanning without data sharing or telemetry.

## Features

- 🛡️ **Multi-Engine Scanning**: Combines multiple detection engines for comprehensive protection
- 🔍 **ClamAV Integration**: Leverages the popular open-source antivirus engine
- #️⃣ **Hash-Based Detection**: Uses MD5, SHA-1, and SHA-256 signatures to identify known malware
- 📁 **Directory Scanning**: Recursively scan entire directories
- 🚀 **Fast & Lightweight**: Minimal resource usage
- 🔒 **Privacy-First**: No data collection, no telemetry, completely offline
- ☕ **Pure Java**: Cross-platform compatibility (Windows, Linux, macOS)

## Prerequisites

- Java 11 or higher
- Maven 3.6+ (for building from source)
- ClamAV (optional, for ClamAV scanning features)

### Installing ClamAV (Optional)

**Ubuntu/Debian:**
```bash
sudo apt-get install clamav clamav-daemon
```

**macOS:**
```bash
brew install clamav
```

**Windows:**
Download from [ClamAV official website](https://www.clamav.net/downloads)

## Building from Source

```bash
git clone https://github.com/LordAlastor78/Haztya.git
cd Haztya
mvn clean package
```

This will create `haztya-1.0.0.jar` in the `target/` directory.

## Usage

### Scan a File

```bash
java -jar target/haztya-1.0.0.jar scan /path/to/file
```

### Scan a Directory

```bash
java -jar target/haztya-1.0.0.jar scan /path/to/directory
```

### Display Scanner Information

```bash
java -jar target/haztya-1.0.0.jar info
```

### Display Version

```bash
java -jar target/haztya-1.0.0.jar version
```

### Display Help

```bash
java -jar target/haztya-1.0.0.jar help
```

## Architecture

Haztya uses a modular architecture with multiple scanning engines:

```
┌─────────────────────────────────────┐
│     Haztya Main Application         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│      Composite Scanner              │
│  (Coordinates multiple engines)     │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌─────────────┐ ┌─────────────┐
│   ClamAV    │ │ Hash-Based  │
│   Scanner   │ │   Scanner   │
└─────────────┘ └─────────────┘
```

### Components

- **ScanResult**: Data model for scan results
- **MalwareScanner**: Interface for all scanner implementations
- **CompositeScanner**: Coordinates multiple scanning engines
- **ClamAVScanner**: ClamAV integration wrapper
- **HashBasedScanner**: Signature-based detection using file hashes
- **HashUtil**: Utility for calculating file hashes (MD5, SHA-1, SHA-256)

## Detection Methods

### 1. ClamAV Engine
Integrates with ClamAV to detect malware using its extensive virus database.

### 2. Hash-Based Detection
Compares file hashes (MD5, SHA-256) against a database of known malware signatures. Includes support for EICAR test file detection.

### 3. Extensible Architecture
Easy to add new detection engines by implementing the `MalwareScanner` interface.

## Testing

Run the test suite:

```bash
mvn test
```

### EICAR Test File

You can test the scanner with the EICAR test file (a safe file designed to trigger antivirus software):

```bash
# Create EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt

# Scan it
java -jar target/haztya-1.0.0.jar scan eicar.txt
```

The scanner should detect this as malware.

## Development

### Project Structure

```
Haztya/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/haztya/
│   │   │       ├── Haztya.java          # Main application
│   │   │       ├── scanner/             # Scanner implementations
│   │   │       ├── detection/           # Detection engines
│   │   │       ├── clamav/              # ClamAV integration
│   │   │       ├── model/               # Data models
│   │   │       └── util/                # Utilities
│   │   └── resources/
│   └── test/
│       └── java/
│           └── com/haztya/              # Unit tests
├── pom.xml                              # Maven configuration
└── README.md                            # This file
```

### Adding a New Scanner Engine

1. Implement the `MalwareScanner` interface
2. Add your scanner to `CompositeScanner`
3. Update documentation

Example:

```java
public class MyCustomScanner implements MalwareScanner {
    @Override
    public ScanResult scanFile(File file) throws IOException {
        // Your scanning logic here
    }
    
    @Override
    public String getEngineName() {
        return "My Custom Scanner";
    }
    
    @Override
    public boolean isAvailable() {
        // Check if scanner is available
        return true;
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ClamAV](https://www.clamav.net/) - Open-source antivirus engine
- [Apache Commons Codec](https://commons.apache.org/proper/commons-codec/) - Hash calculation utilities
- EICAR - Standard Anti-Virus Test File

## Disclaimer

This tool is for educational and testing purposes. Always use multiple layers of security and keep your malware definitions up to date. Haztya is not a replacement for comprehensive security solutions.

## Security

If you discover a security vulnerability, please email the maintainer directly instead of using the issue tracker.

## Roadmap

- [ ] YARA rules support
- [ ] Real-time file monitoring
- [ ] Web interface
- [ ] REST API
- [ ] Docker container
- [ ] Quarantine functionality
- [ ] Automated database updates
- [ ] Integration with VirusTotal API
- [ ] Heuristic analysis engine

## Contact

Project Link: [https://github.com/LordAlastor78/Haztya](https://github.com/LordAlastor78/Haztya)
