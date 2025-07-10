// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.androidApplication) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.jetbrainsKotlinAndroid) apply false
    alias(libs.plugins.dokka ) apply false
    `maven-publish`
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
}
allprojects {
    repositories {
        google()
        mavenCentral()
        maven(url = "https://repo.danubetech.com/repository/maven-public/")
        maven(url = "https://jitpack.io")
    }
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://central.sonatype.com/api/v1/publisher/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
            username.set(System.getenv("OSSRH_USER"))
            password.set(System.getenv("OSSRH_SECRET"))
        }
    }
}