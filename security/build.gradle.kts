import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.library")
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
            baseName = "Security"
            isStatic = true
        }
    }

    sourceSets {
        commonMain {
            kotlin.srcDir(generateSecurityBuildConfig)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
                implementation("dev.whyoleg.cryptography:cryptography-core:0.6.0")
                implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
            }
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
        }
    }
}

android {
    namespace = "com.ishant.security"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
    }
}
