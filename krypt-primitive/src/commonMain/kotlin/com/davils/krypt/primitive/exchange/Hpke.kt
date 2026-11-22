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

package com.davils.krypt.primitive.exchange

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.internal.Dhkem
import com.davils.krypt.primitive.internal.HpkeCipher
import com.davils.krypt.primitive.internal.Labels
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val MODE_BASE: Int = 0
private const val MODE_PSK: Int = 1
private const val MODE_AUTH: Int = 2
private const val MODE_AUTH_PSK: Int = 3
private const val EXPORT_ONLY: Int = 0xFFFF
private const val MINIMUM_PSK: Int = 32
private const val AES_128_ID: Int = 1
private const val AES_256_ID: Int = 2
private const val CHACHA_ID: Int = 3
private const val SHA256_ID: Int = 1
private const val SHA384_ID: Int = 2
private const val SHA512_ID: Int = 3

/**
 * Hybrid public key encryption of RFC 9180 in all four modes: base, with a pre-shared key, authenticated by a sender
 * key, and both.
 *
 * The sender encapsulates a fresh secret for the recipient's public key and derives an AEAD key, a nonce and an
 * exporter secret from it; the recipient derives the same from its private key and the encapsulated key. Sender
 * authentication works with the DHKEMs only, as RFC 9180 defines.
 *
 * @since 1.0.0
 */
public class Hpke internal constructor(private val crypto: Crypto) {
    /**
     * Sets up a sender.
     *
     * @param suite the cipher suite.
     * @param recipient the public key of the recipient.
     * @param info the application context both sides bind the keys to; empty by default.
     * @param sender the own key pair that authenticates the sender, or null.
     * @param psk the pre-shared key of at least 32 bytes, or null.
     * @param pskId the identifier of [psk], required with it.
     * @return the encapsulated key and the context.
     * @throws IllegalArgumentException if the keys do not fit the suite or [psk] and [pskId] do not match up.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm of the suite.
     * @since 1.0.0
     */
    public suspend fun sender(
        suite: HpkeSuite,
        recipient: PublicKey,
        info: ByteString = ByteString(),
        sender: PrivateKey? = null,
        psk: SecretBytes? = null,
        pskId: ByteString = ByteString(),
    ): HpkeSender = senderWith(
        suite = suite,
        recipient = recipient,
        info = info,
        sender = sender,
        psk = psk,
        pskId = pskId,
        ephemeral = null,
    )

    /**
     * Sets up a recipient.
     *
     * @param suite the cipher suite.
     * @param recipient the own private key, whose public key must be known for a DHKEM.
     * @param encapsulated the encapsulated key from the sender.
     * @param info the application context; empty by default.
     * @param sender the public key of an authenticated sender, or null.
     * @param psk the pre-shared key, or null.
     * @param pskId the identifier of [psk].
     * @return the context, or null if the encapsulated key is malformed.
     * @throws IllegalArgumentException if the keys do not fit the suite or [psk] and [pskId] do not match up.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm of the suite.
     * @since 1.0.0
     */
    public suspend fun recipient(
        suite: HpkeSuite,
        recipient: PrivateKey,
        encapsulated: ByteString,
        info: ByteString = ByteString(),
        sender: PublicKey? = null,
        psk: SecretBytes? = null,
        pskId: ByteString = ByteString(),
    ): HpkeContext? {
        permit(suite = suite, isAuthenticated = sender != null, use = AlgorithmUse.Verify)
        requireFits(suite = suite, family = recipient.family, curve = recipient.curve)
        checkPsk(psk, pskId)
        val isMlKem = suite.kem.family == KeyFamily.MlKem
        val secret = when (isMlKem) {
            true -> crypto.kems.decapsulate(recipient = recipient, encapsulated = encapsulated, algorithm = suite.kem)

            false -> Dhkem(
                crypto,
                suite.kem,
            ).decapsulate(recipient = recipient, encapsulated = encapsulated, sender = sender)
        } ?: return null
        val mode = modeOf(isAuthenticated = sender != null, hasPsk = psk != null)
        return secret.use { shared ->
            schedule(
                suite = suite,
                mode = mode,
                sharedSecret = shared,
                info = info,
                psk = psk,
                pskId = pskId,
            )
        }
    }

    /**
     * Seals one message for [recipient] in base mode.
     *
     * @param suite the cipher suite, which must have an AEAD.
     * @param recipient the public key of the recipient.
     * @param plaintext the message.
     * @param info the application context; empty by default.
     * @param associatedData authenticated context; empty by default.
     * @return the encapsulated key followed by the ciphertext.
     * @throws IllegalArgumentException if the suite exports only or the key does not fit it.
     * @since 1.0.0
     */
    public suspend fun seal(
        suite: HpkeSuite,
        recipient: PublicKey,
        plaintext: ByteString,
        info: ByteString = ByteString(),
        associatedData: ByteString = ByteString(),
    ): ByteString {
        requireNotNull(suite.aead) { "An export-only suite seals nothing" }
        val sender = sender(suite = suite, recipient = recipient, info = info)
        val ciphertext = sender.context.seal(plaintext = plaintext, associatedData = associatedData)
        sender.context.destroy()
        return ByteString(sender.encapsulated.toByteArray() + ciphertext.toByteArray())
    }

    /**
     * Opens one message sealed with [seal].
     *
     * @param suite the cipher suite.
     * @param recipient the own private key.
     * @param sealed the encapsulated key followed by the ciphertext.
     * @param info the application context.
     * @param associatedData authenticated context.
     * @return the plaintext, or null if the message is malformed or not authentic.
     * @throws IllegalArgumentException if the suite exports only or the key does not fit it.
     * @since 1.0.0
     */
    public suspend fun open(
        suite: HpkeSuite,
        recipient: PrivateKey,
        sealed: ByteString,
        info: ByteString = ByteString(),
        associatedData: ByteString = ByteString(),
    ): ByteString? {
        requireNotNull(suite.aead) { "An export-only suite opens nothing" }
        val length = encapsulatedLength(suite)
        val bytes = sealed.toByteArray()
        val context = contextOf(
            suite = suite,
            recipient = recipient,
            bytes = bytes,
            length = length,
            info = info,
        ) ?: return null
        val ciphertext = ByteString(data = bytes, startIndex = length, endIndex = bytes.size)
        val opened = context.open(ciphertext = ciphertext, associatedData = associatedData)
        context.destroy()
        return opened
    }

    internal suspend fun senderWith(
        suite: HpkeSuite,
        recipient: PublicKey,
        info: ByteString,
        sender: PrivateKey?,
        psk: SecretBytes?,
        pskId: ByteString,
        ephemeral: KeyPair?,
    ): HpkeSender {
        permit(suite = suite, isAuthenticated = sender != null, use = AlgorithmUse.Protect)
        requireFits(suite = suite, family = recipient.family, curve = recipient.curve)
        checkPsk(psk, pskId)
        val encapsulation = when (suite.kem.family == KeyFamily.MlKem) {
            true -> crypto.kems.encapsulate(recipient = recipient, algorithm = suite.kem)
            false -> Dhkem(crypto, suite.kem).encapsulate(recipient = recipient, sender = sender, ephemeral = ephemeral)
        }
        val mode = modeOf(isAuthenticated = sender != null, hasPsk = psk != null)
        val context = encapsulation.sharedSecret.use { shared ->
            schedule(suite = suite, mode = mode, sharedSecret = shared, info = info, psk = psk, pskId = pskId)
        }
        return HpkeSender(encapsulated = encapsulation.encapsulated, context = context)
    }

    private suspend fun schedule(
        suite: HpkeSuite,
        mode: Int,
        sharedSecret: SecretBytes,
        info: ByteString,
        psk: SecretBytes?,
        pskId: ByteString,
    ): HpkeContext {
        val labels = Labels(crypto = crypto, suiteId = suiteId(suite), kdf = suite.kdf)
        val pskIdHash = bytesOf(labels.extract(salt = ByteString(), label = "psk_id_hash", inputKey = pskId))
        val infoHash = bytesOf(labels.extract(salt = ByteString(), label = "info_hash", inputKey = info))
        val context = ByteString(byteArrayOf(mode.toByte()) + pskIdHash + infoHash)
        val pskBytes = psk?.reveal { bytes -> ByteString(bytes) } ?: ByteString()
        val secret = sharedSecret.reveal { shared ->
            labels.extract(
                salt = ByteString(shared),
                label = "secret",
                inputKey = pskBytes,
            )
        }
        val cipher = cipherOf(labels = labels, secret = secret, context = context, aead = suite.aead)
        val baseNonce = nonceOf(labels = labels, secret = secret, context = context, aead = suite.aead)
        val exporter = labels.expand(prk = secret, label = "exp", info = context, length = suite.kdf.digest.outputBytes)
        secret.destroy()
        return HpkeContext(
            crypto = crypto,
            suite = suite,
            cipher = cipher,
            baseNonce = baseNonce,
            exporterSecret = exporter,
            labels = labels,
        )
    }

    private suspend fun contextOf(
        suite: HpkeSuite,
        recipient: PrivateKey,
        bytes: ByteArray,
        length: Int,
        info: ByteString,
    ): HpkeContext? {
        if (bytes.size <= length) return null
        val encapsulated = ByteString(data = bytes, startIndex = 0, endIndex = length)
        return recipient(suite = suite, recipient = recipient, encapsulated = encapsulated, info = info)
    }

    private suspend fun cipherOf(
        labels: Labels,
        secret: SecretBytes,
        context: ByteString,
        aead: AeadAlgorithm?,
    ): HpkeCipher? {
        val found = aead ?: return null
        val key = labels.expand(prk = secret, label = "key", info = context, length = found.keyBytes)
        return HpkeCipher(aead = found, key = SecretKey.adopt(key))
    }

    private suspend fun nonceOf(
        labels: Labels,
        secret: SecretBytes,
        context: ByteString,
        aead: AeadAlgorithm?,
    ): ByteArray {
        val found = aead ?: return ByteArray(0)
        return bytesOf(labels.expand(prk = secret, label = "base_nonce", info = context, length = found.nonceBytes))
    }

    private fun requireFits(suite: HpkeSuite, family: KeyFamily, curve: EllipticCurve?) {
        val type = Dhkem.keyTypeOf(suite.kem)
        require(
            type.family == family && type.curve == curve,
        ) { "A $family key does not fit ${suite.kem.algorithmName}" }
    }

    private fun permit(suite: HpkeSuite, isAuthenticated: Boolean, use: AlgorithmUse) {
        crypto.permit(suite.kem, use)
        crypto.permit(suite.kdf, use)
        suite.aead?.let { aead -> crypto.permit(aead, use) }
        require(!isAuthenticated || suite.kem.family != KeyFamily.MlKem) { "ML-KEM cannot authenticate a sender" }
    }

    private fun checkPsk(psk: SecretBytes?, pskId: ByteString) {
        require(psk == null == (pskId.size == 0)) { "A pre-shared key and its identifier come together" }
        require(psk == null || psk.size >= MINIMUM_PSK) { "A pre-shared key has at least $MINIMUM_PSK bytes" }
    }

    private fun modeOf(isAuthenticated: Boolean, hasPsk: Boolean): Int = listOf(
        listOf(MODE_BASE, MODE_PSK),
        listOf(MODE_AUTH, MODE_AUTH_PSK),
    )[isAuthenticated.compareTo(false)][hasPsk.compareTo(false)]

    private fun encapsulatedLength(suite: HpkeSuite): Int = ENCAPSULATED_LENGTHS.getValue(suite.kem)

    private fun bytesOf(secret: SecretBytes): ByteArray = secret.use { owned ->
        owned.reveal { bytes -> bytes.copyOf() }
    }

    private fun suiteId(suite: HpkeSuite): ByteString = ByteString(
        "HPKE".encodeToByteString().toByteArray() +
            Labels.twoBytes(Dhkem.kemId(suite.kem)) +
            Labels.twoBytes(kdfId(suite.kdf)) +
            Labels.twoBytes(aeadId(suite.aead)),
    )

    private fun kdfId(kdf: KdfAlgorithm): Int = KDF_IDS.getValue(kdf.digest.outputBytes)

    private fun aeadId(aead: AeadAlgorithm?): Int {
        val found = aead ?: return EXPORT_ONLY
        return AEAD_IDS.getValue(found)
    }

    private companion object {
        val KDF_IDS: Map<Int, Int> = mapOf(32 to SHA256_ID, 48 to SHA384_ID, 64 to SHA512_ID)

        val AEAD_IDS: Map<AeadAlgorithm, Int> = mapOf(
            AeadAlgorithm.Aes128Gcm to AES_128_ID,
            AeadAlgorithm.Aes256Gcm to AES_256_ID,
            AeadAlgorithm.ChaCha20Poly1305 to CHACHA_ID,
        )

        val ENCAPSULATED_LENGTHS: Map<KemAlgorithm, Int> = mapOf(
            KemAlgorithm.DhkemX25519 to 32,
            KemAlgorithm.DhkemP256 to 65,
            KemAlgorithm.DhkemP384 to 97,
            KemAlgorithm.DhkemP521 to 133,
            KemAlgorithm.MlKem768 to 1_088,
            KemAlgorithm.MlKem1024 to 1_568,
        )
    }
}
