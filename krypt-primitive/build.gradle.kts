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
        description = "The primitives of krypt, the cryptography library of Davils: keys and their encodings, " +
            "digests, MACs, HKDF and PBKDF2, AEAD, key wrap, RSA-OAEP, signatures, key agreement, KEMs, HPKE and " +
            "password hashing, on JCA and WebCrypto."
    }
}

dependencies {
    commonMainApi(project(":krypt-core"))
    commonMainApi(project(":krypt-asn1"))
}
