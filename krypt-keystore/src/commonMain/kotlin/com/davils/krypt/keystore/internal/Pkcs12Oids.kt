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

package com.davils.krypt.keystore.internal

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm

internal object Pkcs12Oids {
    val DATA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.1")
    val ENCRYPTED_DATA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.6")
    val KEY_BAG: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.12.10.1.1")
    val SHROUDED_KEY_BAG: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.12.10.1.2")
    val CERTIFICATE_BAG: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.12.10.1.3")
    val X509_CERTIFICATE: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.22.1")
    val FRIENDLY_NAME: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.20")
    val LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.21")
    val TRUSTED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.113894.746875.1.1")
    val ANY_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier.of("2.5.29.37.0")
    val PBMAC1: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.5.14")
    val PBKDF2: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.5.12")

    val HMACS: Map<ObjectIdentifier, MacAlgorithm> = mapOf(
        ObjectIdentifier.of("1.2.840.113549.2.9") to MacAlgorithm.HmacSha256,
        ObjectIdentifier.of("1.2.840.113549.2.10") to MacAlgorithm.HmacSha384,
        ObjectIdentifier.of("1.2.840.113549.2.11") to MacAlgorithm.HmacSha512,
    )

    val DIGESTS: Map<ObjectIdentifier, DigestAlgorithm> = mapOf(
        ObjectIdentifier.of("2.16.840.1.101.3.4.2.1") to DigestAlgorithm.Sha256,
        ObjectIdentifier.of("2.16.840.1.101.3.4.2.2") to DigestAlgorithm.Sha384,
        ObjectIdentifier.of("2.16.840.1.101.3.4.2.3") to DigestAlgorithm.Sha512,
    )

    val PBKDF2S: Map<DigestAlgorithm, KdfAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to KdfAlgorithm.Pbkdf2Sha256,
        DigestAlgorithm.Sha512 to KdfAlgorithm.Pbkdf2Sha512,
    )

    val HMAC_OF_DIGEST: Map<DigestAlgorithm, MacAlgorithm> = HMACS.values.associateBy { mac -> mac.digest }

    val HMAC_SHA256: ObjectIdentifier = HMACS.keys.first()
}
