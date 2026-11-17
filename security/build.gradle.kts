import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.library")
    id("com.vanniktech.maven.publish")
}

abstract class GenerateSecurityBuildConfigTask : DefaultTask() {
    @get:Input
    abstract val currentVersion: Property<Int>

    @get:Input
    abstract val cipherAlgorithm: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val file = outputDir.get().file("com/ishant/security/SecurityBuildConfig.kt").asFile
        file.parentFile.mkdirs()
        file.writeText(
            """
            package com.ishant.security

            internal object SecurityBuildConfig {
                const val CURRENT_VERSION: Int = ${currentVersion.get()}
                const val ALGORITHM: String = "${cipherAlgorithm.get()}"
            }
            """.trimIndent(),
        )
    }
}

val generateSecurityBuildConfig = tasks.register("generateSecurityBuildConfig", GenerateSecurityBuildConfigTask::class.java) {
    description = "Generates SecurityBuildConfig object containing build constants"
    group = "build"
    currentVersion.set(1)
    cipherAlgorithm.set("AES-256-GCM")
    outputDir.set(layout.buildDirectory.dir("generated/source/buildConfig/commonMain/kotlin"))
}

group = "io.github.kratos1996"
version = "1.0.3"

kotlin {
    androidTarget {
        publishLibraryVariants("release")
    }
    jvm()
    iosArm64()
    iosSimulatorArm64()
    iosX64()

    targets.withType<KotlinNativeTarget>().configureEach {
        binaries.framework {
            baseName = "KMPSecurity"
            isStatic = true
        }
    }

    sourceSets {
        commonMain {
            kotlin.srcDir(generateSecurityBuildConfig)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
                implementation("dev.whyoleg.cryptography:cryptography-core:0.6.0")
                implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
            }
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
        }
    }
}

android {
    namespace = "com.ishant.security"
    compileSdk = 37

    defaultConfig {
        minSdk = 24
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

mavenPublishing {
    publishToMavenCentral()
    if (project.hasProperty("signing.keyId") || project.hasProperty("signing.gnupg.key") || project.hasProperty("signing.secretKeyRingFile")) {
        signAllPublications()
    }
    coordinates("io.github.kratos1996", "kmp-security", "1.0.3")

    pom {
        name.set("KMP_Security")
        description.set("A Kotlin Multiplatform security foundation providing AES-256-GCM, hardware-backed P-256 identity, and ephemeral X25519 handshakes for Compose Multiplatform applications.")
        url.set("https://github.com/Kratos1996/KMP_Security")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("ishant")
                name.set("Ishant")
                email.set("ishant.sharma1947@gmail.com")
            }
        }
        scm {
            connection.set("scm:git:github.com/Kratos1996/KMP_Security.git")
            developerConnection.set("scm:git:ssh://github.com/Kratos1996/KMP_Security.git")
            url.set("https://github.com/Kratos1996/KMP_Security")
        }
    }
}
