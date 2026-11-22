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

package com.davils.krypt.ct.fixture

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyUsage
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

private const val SERIAL: Long = 4_711L
private const val ROOT: String = "Root"

internal class Authority(val certificate: Certificate, val signer: Signer) {
    suspend fun issue(lifetime: Duration = SHORT_DAYS.days): Certificate {
        val pair = crypto.keys.generate(KeyType.P256)
        return leaf(publicKey = pair.publicKey, lifetime = lifetime) { basicConstraints(isCa = false) }
    }

    suspend fun precertified(
        logs: List<TestLog>,
        lifetime: Duration = SHORT_DAYS.days,
        at: Instant = NOW - 1.hours,
        before: ExtensionsBuilder.() -> Unit = { basicConstraints(isCa = false) },
        after: ExtensionsBuilder.() -> Unit = {},
    ): Certificate {
        val pair = crypto.keys.generate(KeyType.P256)
        val precertificate = leaf(publicKey = pair.publicKey, lifetime = lifetime) {
            before()
            after()
        }
        val entry = precertEntry(certificate, precertificate.tbs)
        val timestamps = logs.map { log -> log.sign(entry, at) }
        return leaf(publicKey = pair.publicKey, lifetime = lifetime) {
            before()
            add(transparency.extension(timestamps))
            after()
        }
    }

    private suspend fun leaf(
        publicKey: PublicKey,
        lifetime: Duration,
        extensions: ExtensionsBuilder.() -> Unit,
    ): Certificate {
        val start = NOW - 1.days
        return certificates.issue(signer) {
            serialNumber = DerInteger.of(SERIAL)
            subject { commonName(HOST) }
            issuer = certificate.subject
            this.publicKey = publicKey
            notBefore = start
            notAfter = start + lifetime
            extensions(extensions)
        }
    }

    companion object {
        suspend fun root(): Authority {
            val pair = crypto.keys.generate(KeyType.P256)
            val signer = crypto.signatures.signer(pair.privateKey)
            val certificate = certificates.issue(signer) {
                subject { commonName(ROOT) }
                publicKey = pair.publicKey
                notBefore = NOW - LONG_DAYS.days
                notAfter = NOW + LONG_DAYS.days
                extensions {
                    basicConstraints(isCa = true)
                    keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign))
                }
            }
            return Authority(certificate, signer)
        }
    }
}
