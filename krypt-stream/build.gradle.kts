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
        description = "Bulk data in krypt, the cryptography library of Davils: the KRYPT/1 container with segmented " +
            "streaming encryption, random access, several recipients, key commitment and Merkle trees, and signed " +
            "manifests for large data, for the JVM and WebAssembly."
    }
}

dependencies {
    commonMainApi(project(":krypt-keyset"))
}
