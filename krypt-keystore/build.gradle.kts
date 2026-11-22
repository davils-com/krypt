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
        description = "Key stores of krypt, the cryptography library of Davils: PKCS #12 and PEM bundles read and " +
            "written strictly, identities of a key and its chain, and the loading of material through sources " +
            "the application implements, for the JVM and WebAssembly."
    }
}

dependencies {
    commonMainApi(project(":krypt-x509"))
}
