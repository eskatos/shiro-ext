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

tasks.withType(JavaCompile::class.java) {
    options.encoding = "UTF-8"
}

dependencies {
    "api"("org.apache.shiro:shiro-core:1.2.1")

    implementation("org.bouncycastle:bcprov-jdk16:1.45")
    implementation("org.slf4j:slf4j-api:1.7.1")

    testImplementation("junit:junit:4.7")
}

repositories {
    jcenter()
}
