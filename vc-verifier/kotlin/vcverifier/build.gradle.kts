plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.jetbrainsKotlinAndroid)
    `maven-publish`
    signing
}

android {
    namespace = "io.mosip.vccred.vcverifier"
    compileSdk = 33

    defaultConfig {
        minSdk = 23
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
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

tasks.register<Jar>("jarRelease") {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    dependsOn("assembleRelease")
    from("build/intermediates/javac/release/classes") {
        include("**/*.class")
    }
    from("build/tmp/kotlin-classes/release") {
        include("**/*.class")
    }
    manifest {
        attributes["Implementation-Title"] = project.name
        attributes["Implementation-Version"] = "1.1.0-SNAPSHOT"
    }
    archiveBaseName.set("${project.name}-release")
    archiveVersion.set("1.1.0-SNAPSHOT")
    destinationDirectory.set(layout.buildDirectory.dir("libs"))
}

apply(from = "publish-artifact.gradle")
tasks.register("generatePom") {
    dependsOn("generatePomFileForAarPublication", "generatePomFileForJarReleasePublication")
}