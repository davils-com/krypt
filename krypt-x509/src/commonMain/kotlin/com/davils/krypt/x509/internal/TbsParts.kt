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

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.name.DistinguishedName
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal data class TbsParts(
    val encoded: ByteString,
    val version: Int,
    val serial: DerInteger,
    val algorithm: SignatureAlgorithm?,
    val algorithmEncoding: ByteString,
    val issuer: DistinguishedName,
    val notBefore: Instant,
    val notAfter: Instant,
    val subject: DistinguishedName,
    val spki: ByteString,
    val publicKey: PublicKey?,
    val extensions: Extensions,
    val tbs: ByteString,
)
