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

package com.davils.krypt.keyset.kms

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.provider
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.SecretKey as JcaSecretKey

private const val TRANSFORMATION: String = "AES/GCM/NoPadding"
private const val NONCE_BYTES: Int = 12
private const val TAG_BITS: Int = 128

/**
 * A [KeyManagementService] over an AES key of a JCA provider that may never leave it, such as a key in an HSM behind
 * PKCS #11, sealed with AES-GCM.
 *
 * The cipher comes from the provider of the environment of [crypto] when it names one, and from the provider of [key]
 * otherwise. The nonce is drawn from the randomness of the environment.
 *
 * @param crypto the primitives and their environment.
 * @param key the AES key of the provider.
 * @property keyUri the name of the key, such as `pkcs11:object=master`.
 * @constructor Encrypts with [key].
 * @since 1.0.0
 */
public class ProviderKms(
    private val crypto: Crypto,
    private val key: JcaSecretKey,
    override val keyUri: String,
) : KeyManagementService {
    /**
     * Seals [plaintext] with a fresh nonce.
     *
     * @param plaintext the secret.
     * @param associatedData authenticated context.
     * @return the nonce followed by the sealed data.
     * @since 1.0.0
     */
    override suspend fun encrypt(plaintext: SecretBytes, associatedData: ByteString): ByteString {
        val nonce = crypto.environment.random.bytes(NONCE_BYTES)
        val cipher = cipher(Cipher.ENCRYPT_MODE, nonce, associatedData)
        val sealed = plaintext.reveal { bytes -> cipher.doFinal(bytes) }
        return ByteString(nonce + sealed)
    }

    /**
     * Opens a ciphertext of [encrypt].
     *
     * @param ciphertext the ciphertext.
     * @param associatedData the authenticated context.
     * @return the secret, or null if the ciphertext is malformed or not authentic.
     * @since 1.0.0
     */
    override suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString): SecretBytes? {
        val bytes = ciphertext.toByteArray().takeIf { array -> array.size > NONCE_BYTES } ?: return null
        val nonce = bytes.copyOfRange(fromIndex = 0, toIndex = NONCE_BYTES)
        val cipher = cipher(Cipher.DECRYPT_MODE, nonce, associatedData)
        val opened = try {
            cipher.doFinal(bytes, NONCE_BYTES, bytes.size - NONCE_BYTES)
        } catch (_: AEADBadTagException) {
            null
        }
        return opened?.let { plaintext -> SecretBytes.adopt(plaintext) }
    }

    /**
     * Shows the name of the key.
     *
     * @return the service as text.
     * @since 1.0.0
     */
    override fun toString(): String = "ProviderKms($keyUri)"

    private fun cipher(mode: Int, nonce: ByteArray, associatedData: ByteString): Cipher {
        val provider = crypto.environment.provider
        val cipher = provider?.let { chosen ->
            Cipher.getInstance(
                TRANSFORMATION,
                chosen,
            )
        } ?: Cipher.getInstance(TRANSFORMATION)
        cipher.init(mode, key, GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(associatedData.toByteArray())
        return cipher
    }
}
