plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.jetbrainsKotlinAndroid)
}

android {
    namespace = "io.mosip.vccred.vcverifier"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("info.weboftrust:ld-signatures-java:1.9.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("decentralized-identity:jsonld-common-java:1.8.0")
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")
    implementation("org.springframework:spring-web:6.1.11")
    testImplementation(libs.mockk)


    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}