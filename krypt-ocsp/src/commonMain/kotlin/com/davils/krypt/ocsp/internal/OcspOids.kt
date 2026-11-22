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

@file:OptIn(LegacyCryptography::class)

package com.davils.krypt.ocsp.internal

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm

internal object OcspOids {
    val BASIC: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.48.1.1")
    val NONCE: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.48.1.2")
    val DIGESTS: Map<DigestAlgorithm, ObjectIdentifier> = mapOf(
        DigestAlgorithm.Sha1 to ObjectIdentifier.of("1.3.14.3.2.26"),
        DigestAlgorithm.Sha256 to ObjectIdentifier.of("2.16.840.1.101.3.4.2.1"),
        DigestAlgorithm.Sha384 to ObjectIdentifier.of("2.16.840.1.101.3.4.2.2"),
        DigestAlgorithm.Sha512 to ObjectIdentifier.of("2.16.840.1.101.3.4.2.3"),
    )
    private val ALGORITHMS: Map<ObjectIdentifier, DigestAlgorithm> =
        DIGESTS.entries.associate { (algorithm, oid) -> oid to algorithm }

    fun digestOf(oid: ObjectIdentifier): DigestAlgorithm? = ALGORITHMS[oid]
}
