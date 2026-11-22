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
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevokedCertificate
import com.davils.krypt.x509.extension.Extensions
import com.davils.krypt.x509.name.DistinguishedName
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal data class CrlParts(
    val encoded: ByteString,
    val signatureAlgorithm: SignatureAlgorithm?,
    val issuer: DistinguishedName,
    val thisUpdate: Instant,
    val nextUpdate: Instant?,
    val number: DerInteger?,
    val deltaOf: DerInteger?,
    val issuingDistributionPoint: IssuingDistributionPoint?,
    val extensions: Extensions,
    val unknownCritical: List<ObjectIdentifier>,
    val entries: List<RevokedCertificate>,
    val tbs: ByteString,
)
