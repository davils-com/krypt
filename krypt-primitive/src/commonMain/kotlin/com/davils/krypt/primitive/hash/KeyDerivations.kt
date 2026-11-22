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

package com.davils.krypt.primitive.hash

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_BLOCKS: Int = 255
private const val MINIMUM_SALT: Int = 16

/**
 * Key derivation: HKDF of RFC 5869 and PBKDF2 of RFC 8018.
 *
 * HKDF is computed from the HMAC of the platform on every target, so extract and expand are available on their own as
 * HPKE and TLS need them. PBKDF2 runs on the platform, whose implementation is far faster than a loop of HMAC calls.
 *
 * @since 1.0.0
 */
public class KeyDerivations internal constructor(private val crypto: Crypto) {
    /**
     * Derives [length] bytes from [inputKey] with HKDF: extract with [salt], then expand with [info].
     *
     * @param inputKey the input keying material, such as a shared secret.
     * @param salt the salt; empty means a string of zeros, as RFC 5869 defines.
     * @param info the context that separates derived keys.
     * @param length the number of bytes, from 1 to 255 times the digest length.
     * @param algorithm the HKDF; [KdfAlgorithm.HkdfSha256] by default.
     * @return the derived key.
     * @throws IllegalArgumentException if [algorithm] is not an HKDF or [length] is out of range.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun hkdf(
        inputKey: SecretBytes,
        salt: ByteString,
        info: ByteString,
        length: Int,
        algorithm: KdfAlgorithm = KdfAlgorithm.HkdfSha256,
    ): SecretBytes = extract(salt = salt, inputKey = inputKey, algorithm = algorithm).use { prk ->
        expand(pseudorandomKey = prk, info = info, length = length, algorithm = algorithm)
    }

    /**
     * The extract step of HKDF: HMAC of [inputKey] keyed with [salt].
     *
     * @param salt the salt; empty means a string of zeros.
     * @param inputKey the input keying material.
     * @param algorithm the HKDF; [KdfAlgorithm.HkdfSha256] by default.
     * @return the pseudorandom key.
     * @throws IllegalArgumentException if [algorithm] is not an HKDF.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun extract(
        salt: ByteString,
        inputKey: SecretBytes,
        algorithm: KdfAlgorithm = KdfAlgorithm.HkdfSha256,
    ): SecretBytes {
        val mac = hkdfMac(algorithm)
        val saltBytes = salt.toByteArray().takeIf { bytes -> bytes.isNotEmpty() } ?: ByteArray(
            algorithm.digest.outputBytes,
        )
        val key = SecretKey(SecretBytes.adopt(saltBytes))
        val prk = inputKey.reveal { bytes -> crypto.backend.mac(mac, key, bytes) }
        key.destroy()
        return SecretBytes.adopt(prk)
    }

    /**
     * The expand step of HKDF.
     *
     * @param pseudorandomKey the pseudorandom key from [extract], at least as long as the digest.
     * @param info the context that separates derived keys.
     * @param length the number of bytes, from 1 to 255 times the digest length.
     * @param algorithm the HKDF; [KdfAlgorithm.HkdfSha256] by default.
     * @return the derived key.
     * @throws IllegalArgumentException if [algorithm] is not an HKDF, [length] is out of range or the key is too short.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun expand(
        pseudorandomKey: SecretBytes,
        info: ByteString,
        length: Int,
        algorithm: KdfAlgorithm = KdfAlgorithm.HkdfSha256,
    ): SecretBytes {
        val mac = hkdfMac(algorithm)
        val hashLength = algorithm.digest.outputBytes
        require(
            length in 1..MAXIMUM_BLOCKS * hashLength,
        ) { "HKDF derives 1 to ${MAXIMUM_BLOCKS * hashLength} bytes, not $length" }
        require(pseudorandomKey.size >= hashLength) { "The pseudorandom key of HKDF has at least $hashLength bytes" }
        val key = SecretKey(pseudorandomKey.copy())
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < length) {
            val block = crypto.backend.mac(mac, key, previous + info.toByteArray() + counter.toByte())
            val count = minOf(a = block.size, b = length - written)
            block.copyInto(destination = output, destinationOffset = written, startIndex = 0, endIndex = count)
            previous.fill(0)
            previous = block
            written += count
            counter += 1
        }
        previous.fill(0)
        key.destroy()
        return SecretBytes.adopt(output)
    }

    /**
     * Derives [length] bytes from [password] with PBKDF2.
     *
     * @param password the password, encoded in UTF-8.
     * @param salt the salt, at least 16 random bytes.
     * @param iterations the iteration count, within the bounds of the policy for [use].
     * @param length the number of bytes, from 16 to 1,024.
     * @param algorithm the PBKDF2; [KdfAlgorithm.Pbkdf2Sha256] by default.
     * @param use [AlgorithmUse.Protect] for a new derivation, [AlgorithmUse.Verify] to repeat a stored one.
     * @return the derived key.
     * @throws IllegalArgumentException if [algorithm] is not a PBKDF2, the salt is too short or [length] is out of
     *   range.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] or the count.
     * @since 1.0.0
     */
    public suspend fun pbkdf2(
        password: SecretText,
        salt: ByteString,
        iterations: Int,
        length: Int,
        algorithm: KdfAlgorithm = KdfAlgorithm.Pbkdf2Sha256,
        use: AlgorithmUse = AlgorithmUse.Protect,
    ): SecretBytes {
        require(algorithm.isPasswordBased) { "${algorithm.algorithmName} is not a password derivation" }
        require(salt.size >= MINIMUM_SALT) { "A PBKDF2 salt has at least $MINIMUM_SALT bytes" }
        require(length in SecretKey.MINIMUM_BYTES..MAXIMUM_LENGTH) { "PBKDF2 derives 16 to $MAXIMUM_LENGTH bytes" }
        crypto.permit(algorithm, use)
        if (!crypto.environment.policy.permitsIterations(
                iterations,
                use,
            )
        ) {
            throw PolicyViolationException("$iterations iterations")
        }
        val derived = crypto.backend.pbkdf2(
            digest = algorithm.digest,
            password = password,
            salt = salt.toByteArray(),
            iterations = iterations,
            length = length,
        )
        return SecretBytes.adopt(derived)
    }

    private fun hkdfMac(algorithm: KdfAlgorithm): MacAlgorithm {
        require(!algorithm.isPasswordBased) { "${algorithm.algorithmName} is not an HKDF" }
        crypto.permit(algorithm, AlgorithmUse.Protect)
        return MacAlgorithm.entries.first { mac -> mac.digest == algorithm.digest }
    }

    private companion object {
        const val MAXIMUM_LENGTH: Int = 1_024
    }
}
