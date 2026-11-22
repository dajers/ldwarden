plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.9"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "lab.pavilion"
version = "1.0.0"

repositories { mavenCentral() }

kotlin {
    jvmToolchain(21)
    compilerOptions.freeCompilerArgs.add("-Xannotation-default-target=param-property")
    providers.gradleProperty("organizerTests").orNull?.let { directory ->
        sourceSets.named("test") { kotlin.srcDir(directory) }
    }
}

val legacyClassTools = "org.apache.commons:commons-lang3:3.17.0"
val legacyBridgeGroup = "org.apache.httpcomponents"
val legacyBridgeVersion = "4.5.12"

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("com.h2database:h2")

    implementation("org.apache.commons:commons-configuration2:2.7")
    implementation("net.minidev:json-smart:2.4.8")
    implementation(
        group = "com.google.code.gson",
        name = "gson",
        version = "2.8.8",
    )
    implementation(legacyClassTools)
    implementation("$legacyBridgeGroup:httpclient") {
        version { strictly(legacyBridgeVersion) }
    }
    implementation("org.jsoup:jsoup:1.24.1")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

configurations.named("runtimeClasspath") {
    resolutionStrategy.activateDependencyLocking()
}

tasks.test { useJUnitPlatform() }

tasks.register<Sync>("stageRuntimeJars") {
    from(configurations.runtimeClasspath)
    into(layout.buildDirectory.dir("sca-jars"))
    include("*.jar")
}
