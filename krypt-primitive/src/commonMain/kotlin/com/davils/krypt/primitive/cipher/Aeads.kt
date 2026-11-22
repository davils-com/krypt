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

package com.davils.krypt.primitive.cipher

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Int = 8

/**
 * Authenticated encryption with associated data: AES-GCM and ChaCha20-Poly1305.
 *
 * [seal] draws a random nonce for every message; with AES-GCM a key must then encrypt fewer than 2^32 messages, which
 * the streaming encryption of `krypt-stream` keeps by deriving a key per stream. [open] has exactly one failure: the
 * message is not authentic, whatever the reason, so no padding or tag oracle can arise.
 *
 * @since 1.0.0
 */
public class Aeads internal constructor(private val crypto: Crypto) {
    /**
     * Encrypts [plaintext] under a fresh random nonce.
     *
     * @param key the key, of the length [algorithm] demands.
     * @param plaintext the message.
     * @param associatedData authenticated but not encrypted context, such as a record id; empty by default.
     * @param algorithm the AEAD; [AeadAlgorithm.Aes256Gcm] by default.
     * @return the nonce and the ciphertext.
     * @throws IllegalArgumentException if the key has the wrong length.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun seal(
        key: SecretKey,
        plaintext: ByteString,
        associatedData: ByteString = ByteString(),
        algorithm: AeadAlgorithm = AeadAlgorithm.Aes256Gcm,
    ): SealedBox {
        val nonce = ByteString(crypto.environment.random.bytes(algorithm.nonceBytes))
        val ciphertext = encrypt(
            key = key,
            nonce = nonce,
            plaintext = plaintext,
            associatedData = associatedData,
            algorithm = algorithm,
        )
        return SealedBox(nonce = nonce, ciphertext = ciphertext)
    }

    /**
     * Decrypts and authenticates [box].
     *
     * @param key the key.
     * @param box the nonce and the ciphertext.
     * @param associatedData the context the message was sealed with.
     * @param algorithm the AEAD; [AeadAlgorithm.Aes256Gcm] by default.
     * @return the plaintext, or null if the box is not authentic under this key and context.
     * @throws IllegalArgumentException if the key has the wrong length.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] for verification.
     * @since 1.0.0
     */
    public suspend fun open(
        key: SecretKey,
        box: SealedBox,
        associatedData: ByteString = ByteString(),
        algorithm: AeadAlgorithm = AeadAlgorithm.Aes256Gcm,
    ): ByteString? = decrypt(
        key = key,
        nonce = box.nonce,
        ciphertext = box.ciphertext,
        associatedData = associatedData,
        algorithm = algorithm,
    )

    /**
     * Encrypts [plaintext] under [nonce], for a protocol that derives its nonces, such as a stream of segments or HPKE.
     *
     * A nonce must never repeat under one key: a repeated nonce with AES-GCM reveals the authentication key.
     *
     * @param key the key.
     * @param nonce the nonce, of the length [algorithm] demands.
     * @param plaintext the message.
     * @param associatedData authenticated context.
     * @param algorithm the AEAD.
     * @return the ciphertext followed by the tag.
     * @throws IllegalArgumentException if the key or the nonce has the wrong length.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun encrypt(
        key: SecretKey,
        nonce: ByteString,
        plaintext: ByteString,
        associatedData: ByteString,
        algorithm: AeadAlgorithm,
    ): ByteString {
        check(key = key, nonce = nonce, algorithm = algorithm)
        crypto.permit(algorithm, AlgorithmUse.Protect)
        val sealed = crypto.backend.seal(
            algorithm = algorithm,
            key = key,
            nonce = nonce.toByteArray(),
            aad = associatedData.toByteArray(),
            plaintext = plaintext.toByteArray(),
        )
        return ByteString(sealed)
    }

    /**
     * Decrypts [ciphertext] under [nonce].
     *
     * @param key the key.
     * @param nonce the nonce.
     * @param ciphertext the ciphertext followed by the tag.
     * @param associatedData authenticated context.
     * @param algorithm the AEAD.
     * @return the plaintext, or null if the ciphertext is not authentic.
     * @throws IllegalArgumentException if the key or the nonce has the wrong length.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] for verification.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        key: SecretKey,
        nonce: ByteString,
        ciphertext: ByteString,
        associatedData: ByteString,
        algorithm: AeadAlgorithm,
    ): ByteString? {
        check(key = key, nonce = nonce, algorithm = algorithm)
        crypto.permit(algorithm, AlgorithmUse.Verify)
        val bytes = ciphertext.toByteArray().takeIf { sealed -> sealed.size >= algorithm.tagBytes } ?: return null
        val opened = crypto.backend.open(
            algorithm = algorithm,
            key = key,
            nonce = nonce.toByteArray(),
            aad = associatedData.toByteArray(),
            ciphertext = bytes,
        )
        return opened?.let { plain -> ByteString(plain) }
    }

    private fun check(key: SecretKey, nonce: ByteString, algorithm: AeadAlgorithm) {
        require(
            key.bits == algorithm.keyBytes * BYTE_BITS,
        ) { "${algorithm.algorithmName} needs a key of ${algorithm.keyBytes} bytes" }
        require(
            nonce.size == algorithm.nonceBytes,
        ) { "${algorithm.algorithmName} needs a nonce of ${algorithm.nonceBytes} bytes" }
    }
}
