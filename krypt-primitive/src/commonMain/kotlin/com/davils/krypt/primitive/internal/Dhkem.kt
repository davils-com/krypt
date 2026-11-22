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

package com.davils.krypt.primitive.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.exchange.Encapsulation
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val X25519_ID: Int = 0x0020
private const val P256_ID: Int = 0x0010
private const val P384_ID: Int = 0x0011
private const val P521_ID: Int = 0x0012
private const val ML_KEM_768_ID: Int = 0x0041
private const val ML_KEM_1024_ID: Int = 0x0042

internal class Dhkem(private val crypto: Crypto, private val algorithm: KemAlgorithm) {
    private val labels = Labels(crypto = crypto, suiteId = suiteId(algorithm), kdf = kdfOf(algorithm))

    suspend fun encapsulate(recipient: PublicKey, sender: PrivateKey?, ephemeral: KeyPair? = null): Encapsulation {
        val pair = ephemeral ?: crypto.keys.generate(keyTypeOf(algorithm))
        val enc = serialize(pair.publicKey)
        val first = crypto.agreements.agree(pair.privateKey, recipient)
        val dh = withSender(first = first, sender = sender, peer = recipient)
        val context = enc + serialize(recipient) + senderBytes(sender)
        val secret = extractAndExpand(dh = dh, context = context)
        if (ephemeral == null) pair.privateKey.destroy()
        return Encapsulation(sharedSecret = secret, encapsulated = enc)
    }

    suspend fun decapsulate(recipient: PrivateKey, encapsulated: ByteString, sender: PublicKey?): SecretBytes? {
        val ephemeral = deserialize(encapsulated) ?: return null
        val recipientPublic = checkNotNull(recipient.publicKey) { "The recipient key needs its public key" }
        val first = crypto.agreements.agreeOrNull(recipient, ephemeral)
        val dh = first?.let { secret -> withPeer(first = secret, recipient = recipient, sender = sender) }
        val context = encapsulated + serialize(recipientPublic) + serializeOrEmpty(sender)
        return dh?.let { secret -> extractAndExpand(dh = secret, context = context) }
    }

    fun deserialize(encoded: ByteString): PublicKey? {
        val spki = KeyCodec.spkiOf(algorithm = algorithmIdentifier(), publicBits = BitString(encoded))
        return crypto.keys.decodePublic(spki).getOrNull()
    }

    private fun algorithmIdentifier(): ByteString {
        val curve = curveOf(algorithm) ?: return X25519_ALGORITHM
        return KeyCodec.ecAlgorithm(curve)
    }

    private suspend fun withSender(first: SecretBytes, sender: PrivateKey?, peer: PublicKey): SecretBytes {
        val own = sender ?: return first
        return concat(first = first, second = crypto.agreements.agree(own, peer))
    }

    private suspend fun withPeer(first: SecretBytes, recipient: PrivateKey, sender: PublicKey?): SecretBytes? {
        val peer = sender ?: return first
        val second = crypto.agreements.agreeOrNull(recipient, peer)
        if (second == null) first.destroy()
        return second?.let { found -> concat(first = first, second = found) }
    }

    private fun senderBytes(sender: PrivateKey?): ByteString {
        val own = sender ?: return ByteString()
        return serialize(checkNotNull(own.publicKey) { "The sender key needs its public key" })
    }

    private fun serializeOrEmpty(key: PublicKey?): ByteString {
        val found = key ?: return ByteString()
        return serialize(found)
    }

    private suspend fun extractAndExpand(dh: SecretBytes, context: ByteString): SecretBytes = dh.use { secret ->
        val prk = secret.reveal { bytes ->
            labels.extract(
                salt = ByteString(),
                label = "eae_prk",
                inputKey = ByteString(bytes),
            )
        }
        prk.use { key ->
            labels.expand(
                prk = key,
                label = "shared_secret",
                info = context,
                length = algorithm.secretBytes,
            )
        }
    }

    private fun concat(first: SecretBytes, second: SecretBytes): SecretBytes {
        val joined = first.reveal { a -> second.reveal { b -> a + b } }
        first.destroy()
        second.destroy()
        return SecretBytes.adopt(joined)
    }

    private operator fun ByteString.plus(other: ByteString): ByteString = ByteString(
        toByteArray() + other.toByteArray(),
    )

    companion object {
        private val KDFS: Map<KemAlgorithm, KdfAlgorithm> = mapOf(
            KemAlgorithm.DhkemP384 to KdfAlgorithm.HkdfSha384,
            KemAlgorithm.DhkemP521 to KdfAlgorithm.HkdfSha512,
        )

        private val X25519_ALGORITHM: ByteString = Der.encode { sequence { objectIdentifier(Oids.X25519) } }

        fun serialize(key: PublicKey): ByteString = key.raw

        fun kemId(algorithm: KemAlgorithm): Int = when (algorithm) {
            KemAlgorithm.DhkemX25519 -> X25519_ID
            KemAlgorithm.DhkemP256 -> P256_ID
            KemAlgorithm.DhkemP384 -> P384_ID
            KemAlgorithm.DhkemP521 -> P521_ID
            KemAlgorithm.MlKem768 -> ML_KEM_768_ID
            KemAlgorithm.MlKem1024 -> ML_KEM_1024_ID
        }

        fun suiteId(algorithm: KemAlgorithm): ByteString =
            ByteString("KEM".encodeToByteString().toByteArray() + Labels.twoBytes(kemId(algorithm)))

        fun kdfOf(algorithm: KemAlgorithm): KdfAlgorithm = KDFS[algorithm] ?: KdfAlgorithm.HkdfSha256

        fun keyTypeOf(algorithm: KemAlgorithm): KeyType = when (algorithm) {
            KemAlgorithm.DhkemX25519 -> KeyType.X25519
            KemAlgorithm.DhkemP256 -> KeyType.P256
            KemAlgorithm.DhkemP384 -> KeyType.P384
            KemAlgorithm.DhkemP521 -> KeyType.P521
            KemAlgorithm.MlKem768 -> KeyType.MlKem768
            KemAlgorithm.MlKem1024 -> KeyType.MlKem1024
        }

        fun curveOf(algorithm: KemAlgorithm): EllipticCurve? = keyTypeOf(algorithm).curve
    }
}
