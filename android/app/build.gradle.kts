plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.rootark.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.rootark.android"
        // Proposed floor (API 29) from docs/architecture/android-client-architecture.md. Owner must confirm.
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.2.0-auth-prototype"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("test") {
            // The signed Node fixture is owned by :core. Keep it shared
            // for JVM unit tests only; do not package it in the app APK.
            resources.srcDir(project(":core").file("src/test/resources"))
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

tasks.withType<Test>().configureEach {
    systemProperty("rootark.fixture", rootProject.file("core/src/test/resources/server-responses.json").absolutePath)
}
