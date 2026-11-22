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

package com.davils.krypt.tls.fixture

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.ct.CtLog
import com.davils.krypt.ct.SignedCertificateTimestamp
import com.davils.krypt.ct.Transparency
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val BYTE_BITS: Int = 8
private const val U16: Int = 2
private const val U24: Int = 3
private const val U64: Int = 8

internal class TestLog private constructor(val log: CtLog, private val key: PrivateKey) {
    suspend fun sign(certificate: Certificate, at: Instant): SignedCertificateTimestamp {
        val data = concat(
            number(0L, U16),
            number(at.toEpochMilliseconds(), U64),
            number(0L, U16),
            number(certificate.encoded.size.toLong(), U24),
            certificate.encoded,
            number(0L, U16),
        )
        val signature = crypto.signatures.sign(key = key, data = data, algorithm = SignatureAlgorithm.EcdsaSha256)
        return SignedCertificateTimestamp(
            logId = log.logId,
            timestamp = at,
            extensions = ByteString(),
            hashAlgorithm = SignedCertificateTimestamp.SHA256,
            signatureAlgorithm = SignedCertificateTimestamp.ECDSA,
            signature = signature,
        )
    }

    private fun number(value: Long, count: Int): ByteString =
        ByteString(ByteArray(count) { index -> (value shr (count - 1 - index) * BYTE_BITS).toByte() })

    private fun concat(vararg parts: ByteString): ByteString =
        ByteString(parts.fold(ByteArray(0)) { all, part -> all + part.toByteArray() })

    companion object {
        suspend fun create(operator: String): TestLog {
            val pair = crypto.keys.generate(KeyType.P256)
            return TestLog(Transparency(crypto).log(publicKey = pair.publicKey, operator = operator), pair.privateKey)
        }
    }
}
