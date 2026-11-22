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

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.cms.enveloped.EnvelopedData
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.cms.signed.VerifiedSigner
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.core.environment
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Instant

internal const val CONTENT_TEXT: String = "krypt CMS fixture content\n"

internal val NOW: Instant = Instant.fromEpochSeconds(1_798_761_600L)

internal val CONTENT: ByteString = CONTENT_TEXT.encodeToByteString()

internal val crypto: Crypto = Crypto(environment { clock = FixedClock })

internal val cms: Cms = Cms(crypto)

internal val certificates: Certificates = Certificates(crypto)

internal fun hex(vararg parts: String): ByteString = checkNotNull(Hex.decode(parts.joinToString("")).getOrNull())

internal fun der(block: DerWriter.() -> Unit): ByteString = Der.encode(block)

internal fun certificate(encoded: ByteString): Certificate = checkNotNull(certificates.decode(encoded).getOrNull())

internal suspend fun privateKey(encrypted: ByteString): PrivateKey {
    val password = SecretText.of("fixture")
    return checkNotNull(crypto.keys.decrypt(encrypted, password).getOrNull())
}

internal suspend fun Cms.verified(
    signed: SignedData,
    content: ByteString? = null,
    parameters: SignatureParameters = SignatureParameters(),
): List<VerifiedSigner> = verify(signedData = signed, content = content, parameters = parameters).value()

internal suspend fun Cms.refusal(
    signed: SignedData,
    content: ByteString? = null,
    parameters: SignatureParameters = SignatureParameters(),
): CmsFailure? = verify(signedData = signed, content = content, parameters = parameters).failureOrNull()

internal fun Cms.enveloped(encoded: ByteString): EnvelopedData = decodeEnveloped(encoded).value()

internal suspend fun Cms.opened(data: EnvelopedData, credential: Credential): ByteString =
    decrypt(envelopedData = data, credential = credential).value()

internal suspend fun Cms.refusal(data: EnvelopedData, credential: Credential): CmsFailure? =
    decrypt(envelopedData = data, credential = credential).failureOrNull()

internal fun <T> Outcome<T, CmsFailure>.value(): T = checkNotNull(
    getOrNull(),
) { "failed with ${failureOrNull() ?: "nothing"}" }
