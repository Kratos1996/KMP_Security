plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
}

kotlin {
    jvm()

    sourceSets {
        commonMain.dependencies {
            implementation("dev.whyoleg.cryptography:cryptography-core:0.6.0")
            implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0")
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
