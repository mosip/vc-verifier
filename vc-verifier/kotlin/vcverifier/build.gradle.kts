plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.jetbrainsKotlinAndroid)
    `maven-publish`
    alias(libs.plugins.dokka)
    signing
    id("org.sonarqube") version "5.1.0.4872"
    jacoco
}

jacoco {
    toolVersion = "0.8.8" // Ensure compatibility
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
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        resources {
            excludes += "META-INF/*"
            excludes += "META-INF/spring/aot.factories"
        }
    }
}

dependencies {
    implementation(libs.orgJson)
    implementation(libs.ldSignaturesJava) {
        exclude(group = "com.apicatalog", module = "titanium-json-ld")
    }
    implementation (libs.titaniumJsonLd)
    implementation(libs.okHttp)
    implementation(libs.bouncyCastle)
    implementation(libs.jsonldCommonJava)
    implementation(libs.nimbusJoseJwt)
    implementation(libs.springWeb)
    implementation("co.nstant.in:cbor:0.9")
    implementation ( "com.android.identity:identity-credential:20231002")

    testImplementation(libs.mockk)
    testImplementation(libs.junitJupiter)
}

tasks.withType<Test> {
    useJUnitPlatform()
//    jacoco {
//        isEnabled = true
//    }
//    finalizedBy(tasks.named("jacocoTestReport")) // Generate the Jacoco report after tests
}

tasks.register("jacocoTestReport", JacocoReport::class) {
    dependsOn("test") // Make sure you adjust the task name based on your build variant (e.g., testDebugUnitTest)

    reports {
        xml.required = true
        html.required = true
        csv.required = false
    }

    val kotlinTree = fileTree(
        mapOf(
            "dir" to "${layout.buildDirectory.get()}/tmp/kotlin-classes/debug",
            "includes" to listOf("**/*.class")
        )
    )
    val coverageSourceDirs = arrayOf("src/main/java")

    classDirectories.setFrom(files(kotlinTree))
    sourceDirectories.setFrom(coverageSourceDirs)

    executionData.setFrom(files("${layout.buildDirectory.get()}/jacoco/testDebugUnitTest.exec"))
}

tasks.register<Jar>("jarRelease") {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    dependsOn("assembleRelease")
    dependsOn("dokkaJavadoc")
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

tasks.register<Jar>("javadocJar") {
    dependsOn("dokkaJavadoc")
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml").get().outputs.files)
}
tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    from(android.sourceSets["main"].java.srcDirs)
}

apply(from = "publish-artifact.gradle")
tasks.register("generatePom") {
    dependsOn("generatePomFileForAarPublication", "generatePomFileForJarReleasePublication")
}

sonarqube {
    properties {
        property( "sonar.java.binaries", "build/intermediates/javac/debug")
        property( "sonar.language", "kotlin")
        property( "soanr.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property( "sonar.scm.disabled", "true")
//        Test coverage can be supported with jacoco
//        property( "sonar.coverage.jacoco.xmlReportPaths", "build/reports/jacoco/jacocoTestReport/jacocoTestReport.xml")
    }
}