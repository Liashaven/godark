plugins { id("com.android.application"); id("org.jetbrains.kotlin.android"); id("org.jetbrains.kotlin.plugin.compose") }

// Production signing material is supplied locally or by a secret manager, never committed.
val releaseKeystorePath = System.getenv("GODARK_KEYSTORE")
val releaseKeyAlias = System.getenv("GODARK_KEY_ALIAS")
val releaseStorePassword = System.getenv("GODARK_STORE_PASSWORD")
val releaseKeyPassword = System.getenv("GODARK_KEY_PASSWORD")
val releaseSigningInputs = listOf(releaseKeystorePath, releaseKeyAlias, releaseStorePassword, releaseKeyPassword)
val releaseSigningConfigured = releaseSigningInputs.all { !it.isNullOrBlank() }
if (releaseSigningInputs.any { !it.isNullOrBlank() } && !releaseSigningConfigured) {
    throw GradleException("Set all four GODARK signing environment variables together; do not commit signing credentials.")
}
if (releaseSigningConfigured && !file(releaseKeystorePath!!).isFile) {
    throw GradleException("The file configured by GODARK_KEYSTORE does not exist.")
}

tasks.configureEach {
    if (name == "assembleRelease" || name == "bundleRelease" ||
        (name.startsWith("package") && name.endsWith("Release"))) {
        doFirst {
            if (!releaseSigningConfigured) {
                throw GradleException("A signed release requires GODARK_KEYSTORE, GODARK_KEY_ALIAS, GODARK_STORE_PASSWORD and GODARK_KEY_PASSWORD.")
            }
        }
    }
}

android {
    namespace = "it.blackout.mesh"
    compileSdk = 35
    defaultConfig {
        applicationId = "it.darkproof.mesh"
        minSdk = 26; targetSdk = 34; versionCode = 5; versionName = "0.5"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    signingConfigs {
        create("release") {
            if (releaseSigningConfigured) {
                storeFile = file(releaseKeystorePath!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }
    buildTypes {
        getByName("release") {
            isDebuggable = false
            if (releaseSigningConfigured) signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { compose = true }
    // Native libraries compressed inside the APK: the file people share offline (Quick Share, Bluetooth) is much smaller.
    packaging { jniLibs { useLegacyPackaging = true } }
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies {
    implementation("com.google.android.gms:play-services-nearby:19.3.0")
    implementation("com.google.ai.edge.litertlm:litertlm-android:0.18.1") // on-device AI (Gemma 4); needs Kotlin 2.4
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("com.google.zxing:core:3.5.3") // invite QR codes, offline
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0") // scan invite QR codes; Google's scanner UI, no camera permission
    implementation("org.maplibre.gl:android-sdk:12.3.1") // offline street maps (OpenFreeMap)
    implementation("com.squareup.okhttp3:okhttp:4.12.0") // MapLibre's HTTP client: User-Agent and 4-connection limit
    implementation("info.guardianproject:tor-android:0.4.9.14") // Tor inside the app, for "Connect through Tor" (BSD)
    implementation("org.bouncycastle:bcprov-jdk18on:1.80.2") // ML-KEM-768 for post-quantum keys: Android has none of its own (MIT-style)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303") // Android's org.json is only a stub in unit tests
}

// tor-android declares it must be compiled against API 37.1, which this AGP can't name yet. It runs on API 24+, and
// nothing here uses API 37, so that compile-time check is skipped. Remove this when compileSdk can be 37.1.
tasks.matching { it.name.startsWith("check") && it.name.endsWith("AarMetadata") }.configureEach { enabled = false }
