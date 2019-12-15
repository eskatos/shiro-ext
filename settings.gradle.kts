
rootProject.name = "shiro-ext"

include(":shiro-ext-x509-core")
include(":shiro-ext-x509-web")

project(":shiro-ext-x509-core").projectDir = file("$rootDir/x509/core")
project(":shiro-ext-x509-web").projectDir = file("$rootDir/x509/web")

