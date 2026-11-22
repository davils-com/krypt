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

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.internal.requireSupported
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

/**
 * Encryption with RSA public keys: RSAES-OAEP, and RSAES-PKCS1-v1_5 only to read old data.
 *
 * RSA encrypts only short messages, such as a symmetric key; encrypt data with an AEAD under such a key, or use HPKE.
 *
 * @since 1.0.0
 */
public class AsymmetricEncryptions internal constructor(private val crypto: Crypto) {
    /**
     * Encrypts [plaintext] for the holder of [publicKey].
     *
     * @param publicKey an RSA public key.
     * @param plaintext the message, shorter than the modulus minus the padding.
     * @param algorithm the scheme; [AsymmetricEncryptionAlgorithm.RsaOaepSha256] by default.
     * @return the ciphertext.
     * @throws IllegalArgumentException if [publicKey] is no RSA key.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] or the key size.
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks [algorithm].
     * @throws com.davils.krypt.primitive.CryptoException if the platform refuses the key or [plaintext] is too long
     *   for it; the exception carries nothing of the failure of the platform.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        publicKey: PublicKey,
        plaintext: ByteString,
        algorithm: AsymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm.RsaOaepSha256,
    ): ByteString {
        require(publicKey.family == KeyFamily.Rsa) { "RSA encryption needs an RSA key, not ${publicKey.family}" }
        crypto.permit(algorithm, AlgorithmUse.Protect)
        crypto.permitKey(publicKey, AlgorithmUse.Protect)
        crypto.requireSupported(algorithm)
        return ByteString(crypto.backend.encrypt(algorithm, publicKey, plaintext.toByteArray()))
    }

    /**
     * Decrypts [ciphertext].
     *
     * @param privateKey an RSA private key.
     * @param ciphertext the ciphertext.
     * @param algorithm the scheme; [AsymmetricEncryptionAlgorithm.RsaOaepSha256] by default.
     * @return the plaintext, or null if the ciphertext does not decrypt under this key or the platform refuses the
     *   key.
     * @throws IllegalArgumentException if [privateKey] is no RSA key.
     * @throws IllegalStateException if [privateKey] was destroyed.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm] or the key size.
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks [algorithm].
     * @since 1.0.0
     */
    public suspend fun decrypt(
        privateKey: PrivateKey,
        ciphertext: ByteString,
        algorithm: AsymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm.RsaOaepSha256,
    ): SecretBytes? {
        require(privateKey.family == KeyFamily.Rsa) { "RSA decryption needs an RSA key, not ${privateKey.family}" }
        crypto.permit(algorithm, AlgorithmUse.Verify)
        crypto.permitKey(privateKey, AlgorithmUse.Verify)
        crypto.requireSupported(algorithm)
        val plaintext = crypto.backend.decrypt(algorithm, privateKey, ciphertext.toByteArray())
        return plaintext?.let { plain -> SecretBytes.adopt(plain) }
    }
}
