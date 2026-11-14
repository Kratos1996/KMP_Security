plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
}

sourceSets {
    main {
        kotlin.srcDir("src/jvmMain/kotlin")
    }
}

dependencies {
    implementation(project(":security"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
    implementation("dev.whyoleg.cryptography:cryptography-core:0.6.0")
    implementation("dev.whyoleg.cryptography:cryptography-provider-optimal:0.6.0")
}

application {
    mainClass.set("com.ishant.security.sample.MainKt")
}
