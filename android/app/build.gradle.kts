plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.arcium.messenger"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.arcium.messenger"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.6.0"
        val solanaRpcUrl = project.findProperty("SOLANA_RPC_URL") as String?
            ?: "https://api.devnet.solana.com"
        buildConfigField("String", "SOLANA_RPC_URL", "\"$solanaRpcUrl\"")
        // Runs the instrumentation tests in src/androidTest on a device or
        // emulator. Those are the only place the JNA bridge and the packaged
        // libarcium_core.so are actually executed; local JVM tests in src/test
        // never load native code.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    // x86_64 UniFFI bridge: the CI workflow (.github/workflows/android-native-bridge.yml)
    // generates the UniFFI Kotlin bindings and the cross-compiled libarcium_core.so BEFORE
    // Gradle runs, writing them under these build-output directories. Nothing here is ever
    // committed. Absent those inputs, Gradle simply compiles/packages without them.
    sourceSets {
        getByName("main") {
            kotlin.srcDir(layout.buildDirectory.dir("generated/rustBridge/kotlin"))
            jniLibs.srcDir(layout.buildDirectory.dir("generated/rustBridge/jniLibs"))
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.core)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.kotlinx.coroutines.android)
    debugImplementation(libs.androidx.ui.tooling)

    // Runtime dependency of UniFFI-generated Kotlin bindings (FFI call bridge).
    // Version/coordinate from official UniFFI 0.28.0 docs (kotlin/gradle.md): "JNA 5.12.0
    // or greater is required" with example net.java.dev.jna:jna:5.12.0@aar.
    implementation("net.java.dev.jna:jna:5.12.0@aar")

    // Local JVM unit tests only (src/test). These cover pure Kotlin logic that
    // must hold before any FFI call happens — the identity-binding checks.
    // Nothing here runs on a device and nothing here loads native code; anything
    // reaching JNA belongs in src/androidTest instead.
    testImplementation(libs.junit)

    // Instrumentation tests only (src/androidTest): the AndroidJUnitRunner and
    // the JUnit4 Android bridge. Deliberately nothing else — no Espresso, no
    // Compose UI testing, no mocking framework. This suite exercises the real
    // FFI chain, so a mock would defeat its purpose.
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
