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

package com.davils.krypt.x509.internal

import com.davils.krypt.asn1.ObjectIdentifier

internal object X509Oids {
    val SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.11")
    val SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.12")
    val SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.13")
    val RSASSA_PSS: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.10")
    val MGF1: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.8")
    val ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.4.3.2")
    val ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.4.3.3")
    val ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.4.3.4")
    val ED25519: ObjectIdentifier = ObjectIdentifier.of("1.3.101.112")
    val ED448: ObjectIdentifier = ObjectIdentifier.of("1.3.101.113")
    val ML_DSA_44: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.3.17")
    val ML_DSA_65: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.3.18")
    val ML_DSA_87: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.3.19")
    val SHA256: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.1")
    val SHA384: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.2")
    val SHA512: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.3")
    val EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.14")
}
