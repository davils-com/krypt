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

package com.davils.krypt.testing.acme

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private const val CERTIFICATE_DAYS: Int = 90
private const val ROOT_DAYS: Int = 3_650

internal class FakeIssuer(private val crypto: Crypto) {
    private val certificates = Certificates(crypto)
    private var authority: Authority? = null

    suspend fun issue(
        publicKey: PublicKey,
        names: List<GeneralName>,
        notBefore: Instant?,
        notAfter: Instant?,
    ): Pair<List<Certificate>, List<Certificate>> {
        val found = authority()
        val start = notBefore ?: crypto.environment.clock.now()
        val leaf = certificates.issue(found.signer) {
            issuer = found.name
            this.publicKey = publicKey
            this.notBefore = start
            this.notAfter = notAfter ?: (start + CERTIFICATE_DAYS.days)
            extensions {
                subjectAlternativeNames(names = names, critical = true)
                authorityKeyIdentifier(found.keyIdentifier)
            }
        }
        return listOf(leaf, found.root) to listOf(leaf, found.cross)
    }

    private suspend fun authority(): Authority {
        val existing = authority
        if (existing != null) return existing
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = crypto.signatures.signer(pair.privateKey)
        val keyIdentifier = certificates.keyIdentifier(pair.publicKey)
        val name = distinguishedName { commonName("krypt fake ACME root") }
        val now = crypto.environment.clock.now()
        val created = Authority(
            signer = signer,
            name = name,
            keyIdentifier = keyIdentifier,
            root = root(signer = signer, name = name, now = now),
            cross = root(signer = signer, name = name, now = now),
        )
        authority = created
        return created
    }

    private suspend fun root(signer: Signer, name: DistinguishedName, now: Instant): Certificate =
        certificates.issue(signer) {
            subject = name
            publicKey = signer.publicKey
            notBefore = now
            notAfter = now + ROOT_DAYS.days
            extensions { basicConstraints(isCa = true) }
        }

    private data class Authority(
        val signer: Signer,
        val name: DistinguishedName,
        val keyIdentifier: ByteString,
        val root: Certificate,
        val cross: Certificate,
    )
}
