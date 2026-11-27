/*
 * Copyright 2026 Davils
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    id("krypt.kotlin-library")
}

kreate {
    project {
        description = "ACME of krypt, the cryptography library of Davils: the client logic of RFC 8555 over a " +
            "transport of the application, with accounts and external account binding, orders, the http-01, " +
            "dns-01 and tls-alpn-01 challenges, revocation and renewal information, for the JVM and WebAssembly."
    }
}

dependencies {
    commonMainApi(project(":krypt-jose"))
    commonMainApi(libs.kontinuity.retry)
}

val testConfigurations: Set<String> = setOf("commonUnitTestImplementation", "wasmJsTestImplementation")

configurations.matching { configuration -> configuration.name in testConfigurations }.configureEach {
    dependencies.add(project.dependencies.create(project(":krypt-testing")))
}
