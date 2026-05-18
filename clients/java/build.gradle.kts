plugins {
    base
}

allprojects {
    group = "health.varta"
    version = providers.gradleProperty("version").get()
}
