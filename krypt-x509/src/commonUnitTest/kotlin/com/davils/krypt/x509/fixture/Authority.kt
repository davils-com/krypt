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

package com.davils.krypt.x509.fixture

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.distinguishedName
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

internal class Authority(val certificate: Certificate, val signer: Signer) {
    suspend fun issue(
        name: String,
        isCa: Boolean = false,
        type: KeyType = KeyType.P256,
        notBefore: Instant = NOW - DAYS.days,
        notAfter: Instant = NOW + DAYS.days,
        subject: DistinguishedName = distinguishedName { commonName(name) },
        extensions: ExtensionsBuilder.() -> Unit = defaultsOf(isCa),
    ): Authority {
        val pair = crypto.keys.generate(type)
        val issued = certificates.issue(signer) {
            this.subject = subject
            issuer = certificate.subject
            publicKey = pair.publicKey
            this.notBefore = notBefore
            this.notAfter = notAfter
            extensions(extensions)
        }
        return Authority(issued, crypto.signatures.signer(pair.privateKey))
    }

    companion object {
        suspend fun root(
            name: String = ROOT,
            type: KeyType = KeyType.P256,
            extensions: ExtensionsBuilder.() -> Unit = defaultsOf(true),
        ): Authority {
            val pair = crypto.keys.generate(type)
            val signer = crypto.signatures.signer(pair.privateKey)
            val certificate = certificates.issue(signer) {
                subject { commonName(name) }
                publicKey = pair.publicKey
                notBefore = NOW - DAYS.days
                notAfter = NOW + DAYS.days
                extensions(extensions)
            }
            return Authority(certificate, signer)
        }

        fun defaultsOf(isCa: Boolean): ExtensionsBuilder.() -> Unit = {
            basicConstraints(isCa = isCa)
            val usages = listOf(setOf(KeyUsage.DigitalSignature), setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign))
            keyUsage(usages[isCa.compareTo(false)])
        }
    }
}
