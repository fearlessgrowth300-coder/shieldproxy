plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.privacyshield.proxy.probe"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.privacyshield.proxy.probe"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
