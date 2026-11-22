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

package com.davils.krypt.keystore.fixture

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keystore.Identities
import com.davils.krypt.keystore.Identity
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.KeyUsage
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

internal const val ITERATIONS: Int = 1_000
private const val DAYS: Int = 30

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val crypto: Crypto = Crypto(environment { policy = cryptoPolicy { minimumIterations = ITERATIONS } })

internal val certificates: Certificates = Certificates(crypto)

internal fun password(text: String = FIXTURE_PASSWORD): SecretText = SecretText.of(text)

internal fun der(block: DerWriter.() -> Unit): ByteString = Der.encode(block)

internal suspend fun issue(
    name: String,
    issuer: Issued? = null,
    type: KeyType = KeyType.P256,
    isCa: Boolean = false,
): Issued {
    val pair = crypto.keys.generate(type)
    val signing = issuer?.pair ?: pair
    val issuerName = issuer?.run { certificate.subject }
    val certificate = certificates.issue(crypto.signatures.signer(signing.privateKey)) {
        subject { commonName(name) }
        issuerName?.let { distinguished -> this.issuer = distinguished }
        publicKey = pair.publicKey
        notBefore = NOW - DAYS.days
        notAfter = NOW + DAYS.days
        extensions {
            basicConstraints(isCa = isCa)
            keyUsage(setOf(KeyUsage.DigitalSignature, KeyUsage.KeyCertSign))
        }
    }
    return Issued(pair, certificate)
}

internal suspend fun identity(name: String = "server", type: KeyType = KeyType.P256): Pair<Identity, Issued> {
    val root = issue(name = "Root of $name", isCa = true)
    val leaf = issue(name = name, issuer = root, type = type)
    val identity = Identities(crypto).of(leaf.pair.privateKey, listOf(root.certificate, leaf.certificate))
    return checkNotNull(identity.getOrNull()) to root
}
