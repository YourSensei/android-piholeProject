plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "com.example.dnsblock"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.example.dnsblock"
        minSdk = 24
        targetSdk = 33
        versionCode = 4
        versionName = "1.3"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
