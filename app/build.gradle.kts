plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val suiteKeystorePath = providers.environmentVariable("SHIELD_SUITE_KEYSTORE")
    .orElse(providers.gradleProperty("shieldSuiteKeystore")).orNull
val suiteStorePassword = providers.environmentVariable("SHIELD_SUITE_STORE_PASSWORD")
    .orElse(providers.gradleProperty("shieldSuiteStorePassword")).orNull
val suiteKeyAlias = providers.environmentVariable("SHIELD_SUITE_KEY_ALIAS")
    .orElse(providers.gradleProperty("shieldSuiteKeyAlias")).orNull
val suiteKeyPassword = providers.environmentVariable("SHIELD_SUITE_KEY_PASSWORD")
    .orElse(providers.gradleProperty("shieldSuiteKeyPassword")).orNull
val suiteSigningReady = listOf(
    suiteKeystorePath, suiteStorePassword, suiteKeyAlias, suiteKeyPassword
).all { !it.isNullOrBlank() }
val buildVersionCode = providers.gradleProperty("buildVersionCode")
    .orElse(providers.environmentVariable("BUILD_VERSION_CODE"))
    .orNull
    ?.toIntOrNull()
    ?: ((System.currentTimeMillis() / 1000L) - 1_577_836_800L).toInt()

check(buildVersionCode in 1..2_100_000_000) {
    "buildVersionCode must be between 1 and 2100000000"
}

android {
    namespace = "com.privacyshield.proxy"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.privacyshield.proxy"
        minSdk = 24
        targetSdk = 36
        // Seconds since 2020-01-01. Every independently started build receives a
        // greater installable version unless CI supplies an explicit override.
        versionCode = buildVersionCode
        versionName = "9.3"

        ndk {
            // Match the ABIs the Mihomo .aar was built for (arm64/arm/x86_64).
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    signingConfigs {
        create("suiteRelease") {
            if (suiteSigningReady) {
                storeFile = file(suiteKeystorePath!!)
                storePassword = suiteStorePassword
                keyAlias = suiteKeyAlias
                keyPassword = suiteKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            // Never let Gradle create/use its machine-specific debug keystore.
            signingConfig = signingConfigs.getByName("suiteRelease")
        }
        release {
            signingConfig = signingConfigs.getByName("suiteRelease")
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
        viewBinding = true
    }
}

gradle.taskGraph.whenReady {
    val packagesApplication = gradle.startParameter.taskNames.any { requested ->
        val task = requested.substringAfterLast(':').lowercase()
        task.startsWith("assemble") ||
            task.startsWith("bundle") ||
            task.startsWith("package") ||
            task.startsWith("install") ||
            task.startsWith("publish") ||
            task == "build" ||
            task.startsWith("buildneeded") ||
            task.startsWith("builddependents")
    }
    if (packagesApplication) {
        check(suiteSigningReady) {
            "Debug and release signing are locked to the permanent suite key. Set SHIELD_SUITE_KEYSTORE, " +
                "SHIELD_SUITE_STORE_PASSWORD, SHIELD_SUITE_KEY_ALIAS, and " +
                "SHIELD_SUITE_KEY_PASSWORD (or the matching shieldSuite* Gradle properties)."
        }
        check(file(suiteKeystorePath!!).isAbsolute && file(suiteKeystorePath).isFile) {
            "SHIELD_SUITE_KEYSTORE must be an existing absolute keystore path."
        }
    }
}

dependencies {
    // Mihomo (Clash.Meta) engine, built via gomobile bind (app/libs/clashcore.aar).
    implementation(files("libs/clashcore.aar"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.documentfile:documentfile:1.0.1")
    testImplementation("junit:junit:4.13.2")
    // Android's local-test JSONObject is a stub; use the matching standalone implementation so
    // verified exit metadata acceptance/rejection tests execute the real parser.
    testImplementation("org.json:json:20240303")
}
