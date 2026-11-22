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

package com.davils.krypt.cms.internal

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.enveloped.RecipientType
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import kotlinx.io.bytestring.ByteString

internal sealed interface ParsedRecipient {
    data class Transport(
        val reference: CertificateReference,
        val algorithm: AsymmetricEncryptionAlgorithm,
        val encryptedKey: ByteString,
    ) : ParsedRecipient

    data class Agreement(
        val originatorAlgorithm: ObjectIdentifier,
        val originatorKey: ByteString,
        val userKeyingMaterial: ByteString?,
        val scheme: AgreementScheme,
        val wrap: KeyWrapAlgorithm,
        val keys: List<Pair<CertificateReference, ByteString>>,
    ) : ParsedRecipient

    data class Kek(val keyIdentifier: ByteString, val wrap: KeyWrapAlgorithm, val encryptedKey: ByteString) :
        ParsedRecipient

    data class Password(
        val derivation: PasswordDerivation,
        val cipher: ContentAlgorithm,
        val encryptedKey: ByteString,
    ) : ParsedRecipient

    data class Kem(
        val reference: CertificateReference,
        val kem: KemAlgorithm,
        val ciphertext: ByteString,
        val kdf: KdfAlgorithm,
        val userKeyingMaterial: ByteString?,
        val wrap: KeyWrapAlgorithm,
        val encryptedKey: ByteString,
    ) : ParsedRecipient

    data class Unsupported(
        val type: RecipientType,
        val references: List<CertificateReference>,
        val keyIdentifier: ByteString?,
    ) : ParsedRecipient

    data class AgreementScheme(val digest: DigestAlgorithm, val isHkdf: Boolean)

    data class PasswordDerivation(val salt: ByteString, val iterations: Int, val prf: DigestAlgorithm)
}
