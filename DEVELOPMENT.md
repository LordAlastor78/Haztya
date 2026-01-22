# Haztya - Guía de Desarrollo

## 🏗️ Arquitectura Detallada

### Patrón de Diseño
El proyecto sigue una arquitectura **modular en capas**:

```
┌─────────────────────────────────────┐
│         UI Layer (Activity)         │
│      MainActivity, Adapters         │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│      Engine Layer (Business)        │
│   ScanEngine, RealtimeMonitor       │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│       Core Layer (Data)             │
│  HashCalculator, SignatureDatabase  │
└─────────────────────────────────────┘
```

### Componentes Principales

#### 1. HashCalculator (`core/HashCalculator.java`)
**Responsabilidad**: Cálculo eficiente de hashes criptográficos

**Características**:
- Cálculo multi-algoritmo en un solo paso
- Soporte para MD5, SHA-1, SHA-256, SHA-512
- Fuzzy hashing para detección de variantes
- Buffer optimizado de 8KB

**Ejemplo de uso**:
```java
File file = new File("/path/to/file");
ConcurrentHashMap<HashType, String> hashes = HashCalculator.calculateAllHashes(file);

String md5 = hashes.get(HashType.MD5);
String sha256 = hashes.get(HashType.SHA256);
```

#### 2. SignatureDatabase (`core/SignatureDatabase.java`)
**Responsabilidad**: Gestión de firmas de malware

**Estructuras de datos**:
- **BloomFilter**: Búsqueda rápida O(k) con 0.1% falsos positivos
- **ConcurrentHashMap**: Almacenamiento preciso thread-safe
- **YARA patterns**: Detección basada en reglas (futuro)

**Operaciones**:
```java
SignatureDatabase db = new SignatureDatabase();

// Agregar firma
MalwareSignature sig = new MalwareSignature(
    "5d41402abc4b2a76b9719d911017c592",  // MD5
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", // SHA1
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // SHA256
    "Win32.Trojan.Generic",
    "Trojan",
    ThreatLevel.HIGH,
    "Generic trojan detection",
    "ClamAV"
);
db.addSignature(sig);

// Verificar archivo
if (db.mightContain(md5Hash, HashType.MD5)) {
    MalwareSignature match = db.getSignature(md5Hash, HashType.MD5);
    if (match != null) {
        System.out.println("Threat detected: " + match.getMalwareName());
    }
}

// Guardar/Cargar
db.saveToDisk(new File("signatures.db"));
db.loadFromDisk(new File("signatures.db"));
```

#### 3. ScanEngine (`engine/ScanEngine.java`)
**Responsabilidad**: Motor de escaneo multi-threaded

**Flujo de escaneo**:
1. Recibe lista de archivos
2. Crea thread pool adaptativo
3. Para cada archivo:
   - Calcula hashes
   - Verifica firmas (signature-based)
   - Análisis heurístico
   - Análisis específico APK (si aplica)
4. Notifica resultados mediante listeners

**Métodos de detección**:

##### a) Signature-based
```java
private MalwareSignature performSignatureCheck(File file) {
    ConcurrentHashMap<HashType, String> hashes = 
        HashCalculator.calculateAllHashes(file);
    
    for (HashType type : HashType.values()) {
        String hash = hashes.get(type);
        if (signatureDatabase.mightContain(hash, type)) {
            return signatureDatabase.getSignature(hash, type);
        }
    }
    return null;
}
```

##### b) Heuristic Analysis
```java
private boolean performHeuristicAnalysis(File file, ScanResult result) {
    int suspicionScore = 0;
    
    // Entropía alta = archivo empaquetado/cifrado
    double entropy = calculateEntropy(file);
    if (entropy > 7.5) suspicionScore += 30;
    
    // Extensión sospechosa
    if (file.getName().endsWith(".exe")) suspicionScore += 50;
    
    // Doble extensión (file.pdf.exe)
    if (file.getName().matches(".*\\.[a-z]{3,4}\\.[a-z]{3,4}$")) {
        suspicionScore += 40;
    }
    
    return suspicionScore > 50;
}
```

##### c) Entropy Calculation
```java
private double calculateEntropy(File file) {
    int[] frequency = new int[256];
    int totalBytes = 0;
    
    // Leer muestra del archivo (primeros 1MB)
    byte[] buffer = new byte[8192];
    FileInputStream fis = new FileInputStream(file);
    
    while (bytesRead != -1 && totalBytes < 1MB) {
        for (byte b : buffer) {
            frequency[b & 0xFF]++;
            totalBytes++;
        }
    }
    
    // Calcular entropía de Shannon
    double entropy = 0.0;
    for (int count : frequency) {
        if (count > 0) {
            double p = (double) count / totalBytes;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
    }
    
    return entropy; // 0.0 - 8.0
}
```

#### 4. RealtimeMonitor (`realtime/RealtimeMonitor.java`)
**Responsabilidad**: Monitoreo en tiempo real del sistema de archivos

**Funcionamiento**:
1. Crea FileObserver recursivo para cada directorio
2. Escucha eventos: CREATE, MODIFY, MOVED_TO, CLOSE_WRITE
3. Aplica cooldown de 2 segundos por archivo
4. Escanea archivos nuevos/modificados en background
5. Notifica amenazas inmediatamente

**Eventos monitoreados**:
```java
FileObserver observer = new FileObserver(path, OBSERVER_EVENTS) {
    @Override
    public void onEvent(int event, String fileName) {
        switch (event) {
            case FileObserver.CREATE:
                // Archivo nuevo creado
                break;
            case FileObserver.MODIFY:
                // Archivo modificado
                break;
            case FileObserver.CLOSE_WRITE:
                // Escritura completa (mejor momento para escanear)
                handleFileEvent(new File(directory, fileName));
                break;
        }
    }
};
```

#### 5. DatabaseDownloader (`network/DatabaseDownloader.java`)
**Responsabilidad**: Descarga y actualización de bases de datos

**Optimizaciones**:
- Usa HTTP ETags para descargar solo si hay cambios
- Verificación de integridad con SHA-256
- Descarga paralela de múltiples fuentes
- Reintentos automáticos en caso de fallo

**Flujo de actualización**:
```java
// 1. Verificar versión actual (ETag)
connection.setRequestProperty("If-None-Match", storedETag);

// 2. Servidor responde
if (responseCode == 304) {
    // No modificado - usar caché local
} else if (responseCode == 200) {
    // Descargar nueva versión
    downloadDatabase();
    
    // 3. Verificar integridad
    if (verifyHash(downloadedFile, expectedSHA256)) {
        // 4. Guardar ETag para próxima vez
        storeETag(connection.getHeaderField("ETag"));
    }
}
```

## 🧪 Testing

### Unit Tests
```java
// HashCalculatorTest.java
@Test
public void testMultiHashCalculation() {
    File testFile = createTestFile("test.txt", "Hello World");
    
    ConcurrentHashMap<HashType, String> hashes = 
        HashCalculator.calculateAllHashes(testFile);
    
    assertEquals("b10a8db164e0754105b7a99be72e3fe5", 
                 hashes.get(HashType.MD5));
    assertEquals("0a4d55a8d778e5022fab701977c5d840bbc486d0", 
                 hashes.get(HashType.SHA1));
}

@Test
public void testEntropyCalculation() {
    // Archivo con datos aleatorios = alta entropía
    File randomFile = createRandomFile(1024);
    double entropy = calculateEntropy(randomFile);
    assertTrue(entropy > 7.0);
    
    // Archivo con datos repetidos = baja entropía
    File repetitiveFile = createRepetitiveFile(1024);
    entropy = calculateEntropy(repetitiveFile);
    assertTrue(entropy < 2.0);
}
```

### Integration Tests
```java
// ScanEngineTest.java
@Test
public void testMalwareDetection() {
    SignatureDatabase db = new SignatureDatabase();
    db.addSignature(createTestSignature());
    
    ScanEngine engine = new ScanEngine(db);
    
    File malwareFile = createTestMalware();
    ScanResult result = engine.scanFile(malwareFile);
    
    assertEquals(ScanResult.Status.THREAT_DETECTED, result.getStatus());
    assertNotNull(result.getThreat());
}
```

## 🔧 Configuración de Desarrollo

### Android Studio Setup
1. Instalar Android Studio Arctic Fox o superior
2. Instalar JDK 17
3. Configurar SDK Manager:
   - Android SDK Platform 34
   - Android SDK Build-Tools 34.0.0
   - Android Emulator

### Build Variants
```gradle
buildTypes {
    debug {
        applicationIdSuffix ".debug"
        debuggable true
        minifyEnabled false
    }
    release {
        minifyEnabled true
        shrinkResources true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
    }
}
```

### Gradle Tasks
```bash
# Compilar debug
./gradlew assembleDebug

# Compilar release
./gradlew assembleRelease

# Ejecutar tests
./gradlew test

# Limpiar proyecto
./gradlew clean

# Analizar dependencias
./gradlew app:dependencies
```

## 📊 Profiling y Optimización

### Memory Profiling
```java
// Monitorear uso de memoria
Debug.MemoryInfo memoryInfo = new Debug.MemoryInfo();
Debug.getMemoryInfo(memoryInfo);

Log.d("Memory", "Dalvik Heap: " + memoryInfo.getTotalPss() + " KB");
```

### CPU Profiling
- Usar Android Profiler en Android Studio
- Identificar hotspots en `HashCalculator.calculateAllHashes()`
- Optimizar loops en `calculateEntropy()`

### Benchmarks
```java
// Medir tiempo de escaneo
long startTime = System.nanoTime();
ScanResult result = scanEngine.scanFile(file);
long endTime = System.nanoTime();

double milliseconds = (endTime - startTime) / 1_000_000.0;
Log.d("Benchmark", "Scan time: " + milliseconds + "ms");
```

## 🐛 Debugging Tips

### Logs estratégicos
```java
// En HashCalculator
Log.d("HashCalc", String.format("Calculating hashes for %s (%.2f MB)", 
    file.getName(), file.length() / 1024.0 / 1024.0));

// En ScanEngine
Log.d("ScanEngine", String.format("Scanned %d files, found %d threats", 
    filesScanned.get(), threatsDetected.get()));

// En RealtimeMonitor
Log.d("Realtime", "File event: " + event + " on " + fileName);
```

### Breakpoints útiles
- `ScanEngine.scanFile()` - Inspeccionar flujo de escaneo
- `SignatureDatabase.mightContain()` - Verificar coincidencias
- `RealtimeMonitor.handleFileEvent()` - Debug eventos en tiempo real

## 📚 Referencias

### Algoritmos
- [BloomFilter - Guava](https://github.com/google/guava/wiki/HashingExplained#bloomfilter)
- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [Fuzzy Hashing (ssdeep)](https://ssdeep-project.github.io/ssdeep/index.html)

### Android
- [FileObserver](https://developer.android.com/reference/android/os/FileObserver)
- [WorkManager](https://developer.android.com/topic/libraries/architecture/workmanager)
- [Room Database](https://developer.android.com/training/data-storage/room)

### Seguridad
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [VirusTotal API](https://developers.virustotal.com/reference/overview)
- [YARA Rules](https://yara.readthedocs.io/)

---

**Happy Coding! 🚀**
