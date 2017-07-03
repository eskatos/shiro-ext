plugins {
    `java-library`
}

base {
    archivesBaseName = "shiro-ext-x509-web"
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_6
    targetCompatibility = JavaVersion.VERSION_1_6
}

tasks.withType(JavaCompile::class.java) {
    options.encoding = "UTF-8"
}

dependencies {
    compileOnly("javax.servlet:servlet-api:2.5")

    "api"(project(":shiro-ext-x509-core"))
    "api"("org.apache.shiro:shiro-web:1.2.1")

    testImplementation("junit:junit:4.7")
}

repositories {
    jcenter()
}
