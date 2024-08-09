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
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions {
        jvmTarget = "21"
    }
    packaging {
        resources {
            excludes += "META-INF/*"
            excludes += "META-INF/spring/aot.factories"
        }
    }
}

dependencies {
    implementation(libs.ldSignaturesJava)
    implementation(libs.bouncyCastle)
    implementation(libs.jsonldCommonJava)
    implementation(libs.nimbusJoseJwt)
    implementation(libs.springWeb)

    testImplementation(libs.mockk)
    testImplementation(libs.junit)
}


    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}