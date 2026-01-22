# Haztya - Advanced Malware Scanner for Android

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Java](https://img.shields.io/badge/Java-17-orange.svg)
![Android](https://img.shields.io/badge/Android-7.0%2B-green.svg)
![License](https://img.shields.io/badge/license-AGPL--3.0-red.svg)

## 🛡️ Descripción

**Haztya** es un escáner de malware avanzado de código abierto para Android, diseñado desde cero para ser más rápido, eficiente y potente que su predecesor Hypatia. Incorpora múltiples algoritmos de detección, análisis heurístico y protección en tiempo real.

### Características Principales

#### 🚀 Rendimiento Optimizado
- **Multi-threading avanzado**: Utiliza todos los núcleos del procesador de manera eficiente
- **Cálculo de hashes en un solo paso**: MD5, SHA-1, SHA-256 y SHA-512 simultáneamente
- **Caché inteligente**: Evita escaneos redundantes de archivos ya verificados
- **Bajo consumo de batería**: Diseñado para minimizar el impacto en la autonomía

#### 🔍 Detección Multicapa
1. **Detección basada en firmas**: Usa BloomFilters para búsquedas O(k) ultra-rápidas
2. **Análisis heurístico**: Detecta amenazas desconocidas mediante:
   - Cálculo de entropía (detecta archivos empaquetados/cifrados)
   - Análisis de extensiones sospechosas
   - Detección de doble extensión
   - Análisis de anomalías de tamaño
3. **Análisis de APKs**: Inspección específica de aplicaciones Android
4. **Fuzzy hashing**: Detección de variantes de malware

#### 🛡️ Protección en Tiempo Real
- Monitoreo recursivo del sistema de archivos
- Escaneo automático de archivos nuevos/modificados
- Período de enfriamiento configurable para evitar escaneos repetitivos
- Notificaciones instantáneas de amenazas

#### 📊 Base de Datos Avanzada
- **Múltiples estructuras de datos**:
  - BloomFilters para búsquedas rápidas (0.1% tasa de falsos positivos)
  - HashMaps para coincidencias precisas
  - Soporte para patrones YARA
- **Información detallada de amenazas**:
  - Nombre del malware
  - Familia de malware
  - Nivel de amenaza (LOW, MEDIUM, HIGH, CRITICAL)
  - Fuente de la firma (ClamAV, ESET, etc.)
  - Descripción
- **Actualización eficiente**: Usa ETags HTTP para descargar solo cambios

## 📋 Requisitos del Sistema

- **Android**: 7.0 (Nougat) o superior
- **RAM**: Mínimo 2GB (recomendado 4GB para escaneos completos)
- **Almacenamiento**: 500MB para la aplicación y bases de datos

## 🏗️ Arquitectura del Proyecto

```
com.haztya.scanner/
├── core/                       # Componentes fundamentales
│   ├── HashCalculator.java     # Cálculo de hashes optimizado
│   ├── SignatureDatabase.java  # Gestión de base de datos
│   └── MalwareSignature.java   # Modelo de datos de firmas
│
├── engine/                     # Motor de escaneo
│   ├── ScanEngine.java         # Motor principal multi-threaded
│   └── ScanResult.java         # Resultados de escaneo
│
├── realtime/                   # Protección en tiempo real
│   └── RealtimeMonitor.java    # Monitor recursivo de archivos
│
├── network/                    # Funciones de red
│   └── DatabaseDownloader.java # Descarga de bases de datos
│
└── ui/                         # Interfaz de usuario
    └── MainActivity.java       # Actividad principal
```

## 🔧 Tecnologías y Librerías

### Dependencias Principales
- **AndroidX**: Componentes modernos de Android (AppCompat, RecyclerView, Room)
- **Guava 33.0.0**: BloomFilters y estructuras de datos avanzadas
- **BouncyCastle 1.77**: Criptografía y verificación de firmas
- **Apache Commons**: Utilidades de IO, compresión y colecciones
- **OkHttp 4.12**: Cliente HTTP eficiente
- **Room Database**: Persistencia local para historial de escaneos

### Algoritmos Implementados
- **Hashing**: MD5, SHA-1, SHA-256, SHA-512 (cálculo en un solo paso)
- **Fuzzy Hashing**: Similar a ssdeep para detectar variantes
- **Entropía de Shannon**: Detección de archivos empaquetados/cifrados
- **BloomFilter**: Búsquedas probabilísticas O(k)

## 📊 Comparación con Hypatia Original

| Característica | Hypatia | Haztya |
|---------------|---------|---------|
| Algoritmos de hash | MD5, SHA-1, SHA-256 | MD5, SHA-1, SHA-256, SHA-512, Fuzzy |
| Análisis heurístico | No | ✅ Sí (múltiples indicadores) |
| Cálculo de hashes | 3 pasadas | **1 pasada** (optimizado) |
| Threading | Básico | Avanzado (thread pool adaptativo) |
| Estructura de datos | Solo BloomFilter | BloomFilter + HashMap + YARA |
| Información de amenazas | Limitada | Detallada (familia, nivel, fuente) |
| Análisis de entropía | No | ✅ Sí |
| Detección de variantes | No | ✅ Sí (fuzzy hashing) |
| Java Version | 8 | **17** |
| Min Android API | 16 (Android 4.1) | 24 (Android 7.0) |
| Target SDK | 32 | **34** |
| Arquitectura | Monolítica | **Modular** |
| Room Database | No | ✅ Sí |
| Material Design 3 | No | ✅ Sí |
| Gradle Version | 7.2 | **8.2** |

## 🚀 Compilación e Instalación

### Prerrequisitos
```bash
- JDK 17 o superior
- Android SDK (API 34)
- Gradle 8.2+
```

### Pasos
```bash
# 1. Clonar el repositorio
git clone https://github.com/tuusuario/Haztya.git
cd Haztya

# 2. Compilar el proyecto
./gradlew assembleRelease

# 3. Instalar en dispositivo
adb install app/build/outputs/apk/release/app-release.apk
```

## 📱 Uso

### Escaneo Rápido
Escanea directorios comunes (Descargas, documentos recientes)

### Escaneo Completo
Escanea todo el almacenamiento del dispositivo

### Protección en Tiempo Real
Activa el monitoreo continuo del sistema de archivos

### Actualizar Base de Datos
Descarga las últimas firmas de malware desde servidores remotos

## 🎯 Optimizaciones Técnicas

### 1. Cálculo de Hashes Multi-algoritmo en Un Solo Paso
```java
// Hypatia: 3 lecturas del archivo
String md5 = calculateMD5(file);      // Lectura 1
String sha1 = calculateSHA1(file);    // Lectura 2
String sha256 = calculateSHA256(file); // Lectura 3

// Haztya: 1 sola lectura para todos los hashes
ConcurrentHashMap<HashType, String> hashes = HashCalculator.calculateAllHashes(file);
```

### 2. BloomFilter con Baja Tasa de Falsos Positivos
```java
BloomFilter<String> filter = BloomFilter.create(
    Funnels.stringFunnel(UTF_8),
    10_000_000,  // 10 millones de firmas
    0.001        // 0.1% falsos positivos
);
```

### 3. Thread Pool Adaptativo
```java
// Se adapta automáticamente al número de núcleos
int threadCount = Runtime.getRuntime().availableProcessors();
ExecutorService executor = Executors.newFixedThreadPool(threadCount);
```

### 4. Caché de Escaneos Recientes
```java
// Evita escanear el mismo archivo múltiples veces
ConcurrentHashMap<String, Long> recentScans = new ConcurrentHashMap<>();
if (currentTime - lastScan < COOLDOWN_MS) return; // Skip
```

## 📈 Métricas de Rendimiento Esperadas

| Métrica | Hypatia | Haztya |
|---------|---------|---------|
| Escaneo archivo 1MB | ~20ms | **< 15ms** |
| Escaneo archivo 40MB | ~1000ms | **< 800ms** |
| Memoria (DB cargada) | ~120MB | **< 150MB** |
| Consumo batería (realtime 24h) | ~3% | **< 2%** |
| Throughput | ~30 archivos/seg | **~50 archivos/seg** |

## 🛣️ Roadmap

### v1.1 (Próximamente)
- [ ] Soporte completo para reglas YARA
- [ ] Análisis avanzado de permisos de APK
- [ ] Machine Learning para detección heurística
- [ ] Exportar reportes en PDF/JSON

### v1.2 (Futuro)
- [ ] Cuarentena de archivos infectados
- [ ] Escaneo programado automático
- [ ] Widget de estado en pantalla principal
- [ ] Modo root para escaneo completo del sistema

### v2.0 (Futuro lejano)
- [ ] Análisis de comportamiento en runtime
- [ ] Detección específica de ransomware
- [ ] Análisis de tráfico de red
- [ ] Portal web para gestión remota

## 🔒 Privacidad y Seguridad

- ✅ **100% Offline**: Los archivos nunca salen del dispositivo
- ✅ **Sin rastreo**: No recopilamos datos de usuario
- ✅ **Código abierto**: Completamente auditable
- ✅ **Sin publicidad**: Software libre sin anuncios
- ✅ **Licencia AGPL-3.0**: Libertad garantizada

## 📄 Licencia

Este proyecto está licenciado bajo GNU Affero General Public License v3.0 - ver el archivo [LICENSE](LICENSE) para detalles.

```
Haztya: Advanced Malware Scanner for Android
Copyright (c) 2026 Haztya Development Team

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

## 🙏 Agradecimientos

- **Hypatia** por la inspiración y base conceptual
- **ClamAV** por las bases de datos de firmas (GPLv2)
- **ESET** por bases de datos adicionales (BSD 2-Clause)
- **MalwareBazaar** por firmas de malware (CC0)
- **Comunidad de código abierto** por las excelentes librerías utilizadas

## 🤝 Contribuir

Las contribuciones son bienvenidas! Áreas de interés:
- 🐛 Reportar bugs
- 💡 Sugerir nuevas características
- 📝 Mejorar documentación
- 🌍 Añadir traducciones
- 🔒 Auditoría de seguridad

---

**Made with ❤️ by the Haztya Team**

**Basado en Hypatia - Reimplementado y optimizado desde cero**


