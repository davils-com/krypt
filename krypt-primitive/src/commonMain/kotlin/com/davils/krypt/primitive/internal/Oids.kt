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

package com.davils.krypt.primitive.internal

import com.davils.krypt.asn1.ObjectIdentifier

internal object Oids {
    val RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.1")
    val EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.2.1")
    val ED25519: ObjectIdentifier = ObjectIdentifier.of("1.3.101.112")
    val ED448: ObjectIdentifier = ObjectIdentifier.of("1.3.101.113")
    val X25519: ObjectIdentifier = ObjectIdentifier.of("1.3.101.110")
    val X448: ObjectIdentifier = ObjectIdentifier.of("1.3.101.111")
    val ML_DSA_44: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.3.17")
    val ML_DSA_65: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.3.18")
    val ML_DSA_87: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.3.19")
    val ML_KEM_768: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.4.2")
    val ML_KEM_1024: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.4.3")
    val PBES2: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.5.13")
    val PBKDF2: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.5.12")
    val HMAC_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.9")
    val HMAC_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.10")
    val HMAC_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.11")
    val AES_128_CBC: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.2")
    val AES_256_CBC: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.42")
}
