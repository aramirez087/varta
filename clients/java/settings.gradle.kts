pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
    }
}

rootProject.name = "varta-client-root"

include(":lib")
include(":benchmarks")
include(":examples:basic-uds")
include(":examples:with-payload")
include(":examples:with-signal-handler")
include(":examples:secure-udp")
