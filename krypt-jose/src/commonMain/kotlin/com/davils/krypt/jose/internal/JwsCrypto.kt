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

package com.davils.krypt.jose.internal

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.primitive.signature.SignatureFormat
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Int = 8

internal class JwsCrypto(private val crypto: Crypto) {
    suspend fun sign(algorithm: JwsAlgorithm, key: JoseKey, input: ByteString): ByteString = when (key) {
        is JoseKey.Secret -> macWith(algorithm = algorithm, key = key.key, input = input)
        is JoseKey.Private -> signWith(algorithm = algorithm, key = key.key, input = input)
        is JoseKey.Public -> throw IllegalArgumentException("A public key does not sign")
        is JoseKey.Password -> throw IllegalArgumentException("A password does not sign")
    }

    suspend fun verify(algorithm: JwsAlgorithm, key: JoseKey, input: ByteString, signature: ByteString): Boolean? =
        when (key) {
            is JoseKey.Secret -> verifyMac(algorithm = algorithm, key = key.key, input = input, tag = signature)
            is JoseKey.Public -> verifyKey(algorithm = algorithm, key = key.key, input = input, signature = signature)
            is JoseKey.Private -> null
            is JoseKey.Password -> null
        }

    private suspend fun signWith(algorithm: JwsAlgorithm, key: PrivateKey, input: ByteString): ByteString {
        val signature = signatureOf(algorithm = algorithm, family = key.family, curve = key.curve)
        requireNotNull(signature) { "A ${key.family} key does not sign ${algorithm.algorithmName}" }
        return crypto.signatures.sign(key = key, data = input, algorithm = signature, format = SignatureFormat.Raw)
    }

    private suspend fun verifyMac(
        algorithm: JwsAlgorithm,
        key: SecretKey,
        input: ByteString,
        tag: ByteString,
    ): Boolean? {
        val mac = algorithm.mac?.takeIf { found -> isLongEnough(found, key) } ?: return null
        return crypto.macs.verify(key = key, data = input, tag = tag, algorithm = mac).isValid
    }

    private suspend fun verifyKey(
        algorithm: JwsAlgorithm,
        key: PublicKey,
        input: ByteString,
        signature: ByteString,
    ): Boolean? {
        val found = signatureOf(algorithm = algorithm, family = key.family, curve = key.curve) ?: return null
        val fieldBytes = key.curve?.fieldBytes
        val isSized = fieldBytes == null || signature.size == 2 * fieldBytes
        return isSized && verifyRaw(key = key, input = input, signature = signature, algorithm = found)
    }

    private suspend fun verifyRaw(
        key: PublicKey,
        input: ByteString,
        signature: ByteString,
        algorithm: SignatureAlgorithm,
    ): Boolean {
        val verification = crypto.signatures.verify(
            key = key,
            data = input,
            signature = signature,
            algorithm = algorithm,
            format = SignatureFormat.Raw,
        )
        return verification.isValid
    }

    private suspend fun macWith(algorithm: JwsAlgorithm, key: SecretKey, input: ByteString): ByteString {
        val mac = requireNotNull(algorithm.mac) { "A symmetric key does not sign ${algorithm.algorithmName}" }
        require(isLongEnough(mac, key)) { "${algorithm.algorithmName} needs a longer key" }
        return crypto.macs.mac(key = key, data = input, algorithm = mac)
    }

    private fun isLongEnough(mac: MacAlgorithm, key: SecretKey): Boolean =
        key.bits >= mac.digest.outputBytes * BYTE_BITS

    private fun signatureOf(algorithm: JwsAlgorithm, family: KeyFamily, curve: EllipticCurve?): SignatureAlgorithm? {
        val signature = algorithm.signatures[family]
        val isCurveRight = algorithm.curve == null || algorithm.curve == curve
        return signature.takeIf { isCurveRight }
    }
}
