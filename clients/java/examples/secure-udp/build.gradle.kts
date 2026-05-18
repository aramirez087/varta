plugins {
    application
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
}

dependencies {
    implementation(project(":lib"))
}

application {
    mainClass.set("health.varta.examples.SecureUdp")
}
