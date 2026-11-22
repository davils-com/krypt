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

package com.davils.krypt.cose.key

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseLimits
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.internal.CborReader
import com.davils.krypt.cose.internal.CoseException
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import com.davils.krypt.cose.internal.KeyCodec
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

/**
 * Reads and writes COSE_Key and COSE_KeySet structures of RFC 9052 section 7 with the key types of RFC 9053 and
 * RFC 8230, and computes their thumbprints by RFC 9679.
 *
 * Reading builds the keys of krypt through SubjectPublicKeyInfo and PKCS #8, so the crypto policy of the environment
 * decides which curves and RSA sizes are accepted. Compressed points, RSA keys of more than two primes, key types,
 * curves, algorithms and operations krypt does not implement are refused. A private key read this way is not proven
 * to belong to the public key next to it. The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the bounds of reading.
 * @property mode whether only deterministic CBOR is accepted.
 * @constructor Works with [crypto] within [limits].
 * @since 1.0.0
 */
public class CoseKeys(
    public val crypto: Crypto,
    public val limits: CoseLimits = CoseLimits.Default,
    public val mode: CborMode = CborMode.Deterministic,
) {
    private val codec = KeyCodec(crypto)

    /**
     * Reads a COSE_Key.
     *
     * @param encoded the CBOR encoding, possibly from an attacker.
     * @return the key, [CoseFailure.Malformed] for a broken structure or [CoseFailure.UnsupportedKey] for a key krypt
     *   or its policy does not accept, including a private key whose public coordinates do not belong to it.
     * @since 1.0.0
     */
    public suspend fun decode(encoded: ByteString): Outcome<CoseKey, CoseFailure> = CoseException.outcome {
        val item = present(CborReader.decodeOrNull(encoded, limits.cbor, mode), CoseFailure.Malformed)
        codec.decode(present(item.mapOrNull(), CoseFailure.Malformed))
    }

    /**
     * Reads a COSE_KeySet.
     *
     * @param encoded the CBOR encoding, possibly from an attacker.
     * @return the keys, or why the set or one of its keys was refused.
     * @since 1.0.0
     */
    public suspend fun decodeSet(encoded: ByteString): Outcome<CoseKeySet, CoseFailure> = CoseException.outcome {
        val item = present(CborReader.decodeOrNull(encoded, limits.cbor, mode), CoseFailure.Malformed)
        val entries = present(item.itemsOrNull(), CoseFailure.Malformed)
        ensure(entries.size <= limits.maximumKeys, CoseFailure.Malformed)
        val keys = entries.map { entry -> codec.decode(present(entry.mapOrNull(), CoseFailure.Malformed)) }
        CoseKeySet(keys)
    }

    /**
     * Writes the public parts of [key]: its type, curve, key id, algorithm, operations and public key.
     *
     * @param key an asymmetric key.
     * @return the deterministic encoding.
     * @throws IllegalArgumentException if [key] is symmetric and so has no public part.
     * @since 1.0.0
     */
    public fun encode(key: CoseKey): ByteString {
        require(key.type != CoseKeyType.Symmetric) { "A symmetric COSE key has no public part" }
        return Cbor.encode(codec.encode(key = key, isPrivateIncluded = false))
    }

    /**
     * Writes [key] with its private or secret part, which the caller must protect and destroy.
     *
     * @param key the key, whose private key must be extractable.
     * @return the deterministic encoding.
     * @throws IllegalStateException if the private key is not extractable or was destroyed.
     * @since 1.0.0
     */
    public fun encodePrivate(key: CoseKey): SecretBytes =
        SecretBytes.copyOf(Cbor.encode(codec.encode(key = key, isPrivateIncluded = true)))

    /**
     * Writes the public parts of every key of [keySet].
     *
     * @param keySet the keys, all asymmetric.
     * @return the deterministic encoding.
     * @throws IllegalArgumentException if a key is symmetric.
     * @since 1.0.0
     */
    public fun encodeSet(keySet: CoseKeySet): ByteString {
        require(keySet.keys.none { key -> key.type == CoseKeyType.Symmetric }) { "A symmetric key has no public part" }
        return Cbor.encode(CborArray(keySet.keys.map { key -> codec.encode(key = key, isPrivateIncluded = false) }))
    }

    /**
     * Returns the COSE Key Thumbprint of [key] by RFC 9679: the hash of the deterministic encoding of its required
     * parameters. The thumbprint of a symmetric key is a hash of the key itself.
     *
     * @param key the key.
     * @param digest the hash; SHA-256 by default, which RFC 9679 requires every implementation to support.
     * @return the thumbprint.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [digest].
     * @since 1.0.0
     */
    public suspend fun thumbprint(key: CoseKey, digest: DigestAlgorithm = DigestAlgorithm.Sha256): ByteString =
        crypto.digests.digest(Cbor.encode(codec.required(key)), digest)

    /**
     * Shows the limits and the mode.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CoseKeys($limits, $mode)"
}
