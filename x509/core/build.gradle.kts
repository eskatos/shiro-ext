plugins {
    `java-library`
}

base {
    archivesBaseName = "shiro-ext-x509-core"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_6
    targetCompatibility = JavaVersion.VERSION_1_6
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

dependencies {
    "api"("org.apache.shiro:shiro-core:1.4.2")

    implementation("org.bouncycastle:bcprov-jdk16:1.46")
    implementation("org.slf4j:slf4j-api:1.7.29")

    testImplementation("junit:junit:4.12")
}

repositories {
    jcenter()
}
