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

package com.davils.krypt.spiffe.fixture

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

internal class Authority(val certificate: Certificate, val privateKey: PrivateKey, val signer: Signer) {
    val chain: List<Certificate> get() = listOf(certificate)

    suspend fun issue(
        name: String,
        notBefore: Instant = NOW - DAYS.days,
        notAfter: Instant = NOW + DAYS.days,
        type: KeyType = KeyType.P256,
        extensions: ExtensionsBuilder.() -> Unit,
    ): Authority {
        val pair = crypto.keys.generate(type)
        val issued = certificates.issue(signer) {
            subject { commonName(name) }
            issuer = certificate.subject
            publicKey = pair.publicKey
            this.notBefore = notBefore
            this.notAfter = notAfter
            extensions(extensions)
        }
        return Authority(issued, pair.privateKey, crypto.signatures.signer(pair.privateKey))
    }

    suspend fun leaf(vararg uris: String): Authority = issue(name = LEAF, extensions = leafOf(uris.toList()))

    suspend fun intermediate(vararg uris: String): Authority =
        issue(name = INTERMEDIATE, extensions = signingOf(uris.toList()))

    companion object {
        const val ROOT: String = "Root"
        const val LEAF: String = "leaf"
        const val INTERMEDIATE: String = "Intermediate"

        suspend fun root(vararg uris: String, type: KeyType = KeyType.P256): Authority {
            val pair = crypto.keys.generate(type)
            val signer = crypto.signatures.signer(pair.privateKey)
            val certificate = certificates.issue(signer) {
                subject { commonName(ROOT) }
                publicKey = pair.publicKey
                notBefore = NOW - DAYS.days
                notAfter = NOW + DAYS.days
                extensions(signingOf(uris.toList()))
            }
            return Authority(certificate, pair.privateKey, signer)
        }

        fun signingOf(uris: List<String>): ExtensionsBuilder.() -> Unit = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign))
            if (uris.isNotEmpty()) subjectAlternativeNames(uris.map { uri -> GeneralName.Uri(uri) })
        }

        fun leafOf(
            uris: List<String>,
            usages: Set<KeyUsage> = setOf(KeyUsage.DigitalSignature),
        ): ExtensionsBuilder.() -> Unit = {
            basicConstraints(isCa = false)
            keyUsage(usages)
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth, KeyPurposes.ClientAuth))
            if (uris.isNotEmpty()) subjectAlternativeNames(uris.map { uri -> GeneralName.Uri(uri) })
        }
    }
}
