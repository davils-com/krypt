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
        description = "SPIFFE of krypt, the cryptography library of Davils: SPIFFE ids and trust domains, the " +
            "validation of X.509-SVIDs and JWT-SVIDs, the creation of JWT-SVIDs, trust bundles and their " +
            "federation, and sources of SVIDs and bundles the application feeds, for the JVM and WebAssembly."
    }
}

dependencies {
    commonMainApi(project(":krypt-jose"))
}
