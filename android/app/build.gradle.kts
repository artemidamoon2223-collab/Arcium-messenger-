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

    // x86_64 Rust native bridge (see .github/workflows/android-native-bridge.yml).
    // The Rust build + UniFFI bindgen step runs BEFORE Gradle and writes its
    // outputs under the build directory below — nothing here is ever committed.
    sourceSets {
        getByName("main") {
            kotlin.srcDir(layout.buildDirectory.dir("generated/rustBridge/kotlin"))
            jniLibs.srcDir(layout.buildDirectory.dir("generated/rustBridge/jniLibs"))
        }
    }
}

// Fails the build clearly if the Rust bridge output is missing, instead of
// silently compiling against no native bridge at all.
tasks.register("verifyRustBridgeArtifacts") {
    doFirst {
        val kotlinDir = layout.buildDirectory.dir("generated/rustBridge/kotlin").get().asFile
        val soFile = layout.buildDirectory
            .file("generated/rustBridge/jniLibs/x86_64/libarcium_core.so").get().asFile
        val kotlinFound = kotlinDir.walkTopDown().any { it.name == "arcium_core.kt" }
        if (!kotlinFound || !soFile.exists()) {
            throw GradleException(
                "Rust native bridge output missing. Expected generated Kotlin bindings " +
                    "under $kotlinDir and native library at $soFile. Run the Rust build + " +
                    "UniFFI bindgen step (see .github/workflows/android-native-bridge.yml) " +
                    "before Gradle."
            )
        }
    }
}

tasks.named("preBuild") {
    dependsOn("verifyRustBridgeArtifacts")
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

    // Required at runtime by UniFFI-generated Kotlin bindings (native FFI call
    // bridge) — see .github/workflows/android-native-bridge.yml.
    implementation("net.java.dev.jna:jna:5.13.0@aar")
}
