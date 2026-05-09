plugins {
    java
    alias(libs.plugins.jmh)
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(17) }
}

dependencies {
    jmh(project(":lib"))
    jmh(libs.junixsocket.core)
    jmh(libs.jmh.core)
    jmhAnnotationProcessor(libs.jmh.annprocess)
}

jmh {
    warmupIterations.set(3)
    iterations.set(5)
    fork.set(2)
    timeUnit.set("ns")
    benchmarkMode.set(listOf("avgt", "ss"))
    profilers.set(listOf("gc"))
}
