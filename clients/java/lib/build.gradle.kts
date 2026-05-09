plugins {
    `java-library`
    `maven-publish`
    signing
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    // BASE JAR HAS ZERO RUNTIME DEPS.
    // junixsocket is user-supplied: compileOnly + testImplementation only.
    compileOnly(libs.junixsocket.core)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.assertj.core)
    testImplementation(libs.gson)
    testImplementation(libs.junixsocket.core)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
    }
    // Surface VARTA_WATCH_BIN to interop tests.
    environment("VARTA_WATCH_BIN", System.getenv("VARTA_WATCH_BIN") ?: "")
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "varta-client",
            "Implementation-Version" to project.version,
            "Automatic-Module-Name" to "health.varta.client"
        )
    }
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).apply {
        addStringOption("Xdoclint:none", "-quiet")
        addBooleanOption("html5", true)
    }
}

// Fail the build if the base jar leaks ANY runtime dependency.
val verifyZeroRuntimeDeps by tasks.registering {
    group = "verification"
    description = "Asserts that the base jar declares zero runtime dependencies."
    doLast {
        val runtime = configurations.getByName("runtimeClasspath").resolvedConfiguration.firstLevelModuleDependencies
        if (runtime.isNotEmpty()) {
            val leaked = runtime.joinToString { "${it.moduleGroup}:${it.moduleName}:${it.moduleVersion}" }
            throw GradleException("base jar leaked runtime deps: $leaked")
        }
        println("zero-dep audit: OK (0 runtime dependencies)")
    }
}

tasks.check {
    dependsOn(verifyZeroRuntimeDeps)
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifactId = "varta-client"
            pom {
                name.set("Varta JVM client")
                description.set("Zero-dependency JVM client for the Varta health protocol (VLP v0.2).")
                url.set("https://github.com/aramirez087/Varta")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                    license {
                        name.set("Apache License 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("aramirez087")
                        name.set("Alexander Ramirez")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/aramirez087/Varta.git")
                    developerConnection.set("scm:git:git@github.com:aramirez087/Varta.git")
                    url.set("https://github.com/aramirez087/Varta")
                }
            }
        }
    }
    repositories {
        maven {
            name = "stagingDeploy"
            url = uri(layout.buildDirectory.dir("staging-deploy"))
        }
    }
}

signing {
    val signingKey: String? by project
    val signingPassword: String? by project
    if (signingKey != null && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["mavenJava"])
    }
}
