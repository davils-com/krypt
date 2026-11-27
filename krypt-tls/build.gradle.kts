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
    id("krypt.jvm-library")
}

kreate {
    project {
        description = "TLS of krypt, the cryptography library of Davils: SSLContexts, engines and socket factories " +
            "of JSSE configured from the crypto policy, rotating key and trust managers on krypt's own path " +
            "validation, revocation by stapled OCSP and lists, Certificate Transparency, mutual TLS with peer " +
            "authorization and hot reload of material, for the JVM."
    }
}

dependencies {
    api(project(":krypt-keystore"))
    api(project(":krypt-ocsp"))
    api(project(":krypt-ct"))
    api(project(":krypt-spiffe"))
    implementation(libs.kontinuity.retry)
}

configurations.matching { configuration -> configuration.name == "unitTestImplementation" }.configureEach {
    dependencies.add(project.dependencies.project(":krypt-authority"))
}
