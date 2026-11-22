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

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.ct.CtLog
import com.davils.krypt.ct.SignedCertificateTimestamp
import com.davils.krypt.primitive.key.PrivateKey
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal class TestLog(val log: CtLog, private val key: PrivateKey, private val isRsa: Boolean) {
    suspend fun sign(
        entry: ByteString,
        at: Instant,
        extensions: ByteString = ByteString(),
    ): SignedCertificateTimestamp {
        val data = concat(
            bytes(0, 0),
            number(at.toEpochMilliseconds(), U64),
            entry,
            number(extensions.size.toLong(), U16),
            extensions,
        )
        val algorithm = listOf(
            SignatureAlgorithm.EcdsaSha256,
            SignatureAlgorithm.RsaPkcs1Sha256,
        )[isRsa.compareTo(false)]
        val code = listOf(SignedCertificateTimestamp.ECDSA, SignedCertificateTimestamp.RSA)[isRsa.compareTo(false)]
        val signature = signing.signatures.sign(key = key, data = data, algorithm = algorithm)
        return SignedCertificateTimestamp(
            logId = log.logId,
            timestamp = at,
            extensions = extensions,
            hashAlgorithm = SignedCertificateTimestamp.SHA256,
            signatureAlgorithm = code,
            signature = signature,
        )
    }

    companion object {
        suspend fun create(
            operator: String,
            type: KeyType = KeyType.P256,
            usableFrom: Instant? = null,
            usableUntil: Instant? = null,
        ): TestLog {
            val pair = signing.keys.generate(type)
            val log = transparency.log(
                publicKey = pair.publicKey,
                operator = operator,
                usableFrom = usableFrom,
                usableUntil = usableUntil,
            )
            return TestLog(log = log, key = pair.privateKey, isRsa = pair.publicKey.family == KeyFamily.Rsa)
        }
    }
}
