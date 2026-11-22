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

package com.davils.krypt.cms.fixture

import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import kotlin.time.Duration.Companion.days

private const val DAYS: Int = 365

internal class Pki(private val root: KeyPair, val certificate: Certificate) {
    val parameters: SignatureParameters
        get() = SignatureParameters(
            validator = PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(certificate))),
            validation = ValidationParameters(isRevocationRequired = false),
        )

    suspend fun issue(
        type: KeyType,
        name: String,
        generator: Crypto = crypto,
        extensions: ExtensionsBuilder.() -> Unit = { keyUsage(setOf(KeyUsage.DigitalSignature)) },
    ): Identity {
        val pair = generator.keys.generate(type)
        val keyIdentifier = certificates.keyIdentifier(pair.publicKey)
        val issued = certificates.issue(crypto.signatures.signer(root.privateKey)) {
            subject { commonName(name) }
            issuer = certificate.subject
            publicKey = pair.publicKey
            notBefore = NOW - DAYS.days
            notAfter = NOW + DAYS.days
            extensions {
                subjectKeyIdentifier(keyIdentifier)
                extensions()
            }
        }
        return Identity(pair, issued)
    }

    suspend fun authority(type: KeyType = KeyType.P256): Identity = issue(type, "tsa") {
        keyUsage(setOf(KeyUsage.DigitalSignature))
        extendedKeyUsage(listOf(KeyPurposes.TimeStamping), critical = true)
    }

    companion object {
        suspend fun create(): Pki {
            val pair = crypto.keys.generate(KeyType.P256)
            val root = certificates.issue(crypto.signatures.signer(pair.privateKey)) {
                subject { commonName("krypt CMS test root") }
                publicKey = pair.publicKey
                notBefore = NOW - DAYS.days
                notAfter = NOW + DAYS.days
                extensions {
                    basicConstraints(isCa = true)
                    keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign))
                }
            }
            return Pki(pair, root)
        }
    }
}
