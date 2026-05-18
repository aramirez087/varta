plugins {
    application
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
}

dependencies {
    implementation(project(":lib"))
    runtimeOnly(libs.junixsocket.core)
}

application {
    mainClass.set("health.varta.examples.BasicUds")
}
