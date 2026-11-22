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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.jose.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweAlgorithm.A128GCMKW
import com.davils.krypt.jose.jwe.JweAlgorithm.A128KW
import com.davils.krypt.jose.jwe.JweAlgorithm.A256GCMKW
import com.davils.krypt.jose.jwe.JweAlgorithm.A256KW
import com.davils.krypt.jose.jwe.JweAlgorithm.Dir
import com.davils.krypt.jose.jwe.JweAlgorithm.EcdhEs
import com.davils.krypt.jose.jwe.JweAlgorithm.EcdhEsA128KW
import com.davils.krypt.jose.jwe.JweAlgorithm.EcdhEsA256KW
import com.davils.krypt.jose.jwe.JweAlgorithm.Pbes2Hs256A128KW
import com.davils.krypt.jose.jwe.JweAlgorithm.Pbes2Hs512A256KW
import com.davils.krypt.jose.jwe.JweAlgorithm.RsaOaep256
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val GCM_IV_BYTES: Int = 12
private const val SALT_BYTES: Int = 16
private const val MINIMUM_SALT_BYTES: Int = 8
private const val BYTE_BITS: Int = 8
private const val SEPARATOR: Byte = 0

internal class KeyManagement(
    private val crypto: Crypto,
    private val keys: JsonWebKeys,
    private val limits: JoseLimits,
) {
    suspend fun encrypt(
        recipient: JweRecipient,
        encryption: JweEncryption,
        cek: SecretBytes,
        header: JsonValue.Object,
    ): Wrapped {
        val algorithm = recipient.algorithm
        val key = recipient.key
        val wrapping = Wrapping(recipient = recipient, encryption = encryption, cek = cek, header = header)
        return when (algorithm) {
            Dir -> Wrapped(cek = secretOf(key, encryption.keyBytes).export())
            A128KW, A256KW -> wrapped(kek = secretOf(key, algorithm), cek = cek, wrap = wrapOf(algorithm))
            A128GCMKW, A256GCMKW -> gcmWrapped(kek = secretOf(key, algorithm), cek = cek, gcm = gcmOf(algorithm))
            EcdhEs, EcdhEsA128KW, EcdhEsA256KW -> agreed(wrapping)
            RsaOaep256 -> rsaWrapped(key = key, cek = cek)
            Pbes2Hs256A128KW, Pbes2Hs512A256KW -> passwordWrapped(wrapping)
        }
    }

    suspend fun recover(attempt: Attempt): Unwrapped? = when (attempt.algorithm) {
        Dir -> directBack(attempt)
        A128KW, A256KW -> unwrapped(attempt)
        A128GCMKW, A256GCMKW -> gcmUnwrapped(attempt)
        EcdhEs, EcdhEsA128KW, EcdhEsA256KW -> agreedBack(attempt)
        RsaOaep256 -> rsaBack(attempt)
        Pbes2Hs256A128KW, Pbes2Hs512A256KW -> passwordBack(attempt)
    }

    fun prepare(algorithm: JweAlgorithm, header: JsonValue.Object, encryptedKey: ByteString): RecipientParts {
        val isEmpty = encryptedKey.size == 0
        require(isEmpty == algorithm.isDirect)
        val iv = header.bytes(HeaderNames.IV)
        val tag = header.bytes(HeaderNames.TAG)
        val gcm = algorithm.gcm
        require(gcm == null || (iv?.size == gcm.nonceBytes && tag?.size == gcm.tagBytes))
        val salt = header.bytes(HeaderNames.SALT)
        val count = header.integer(HeaderNames.COUNT)
        if (algorithm.kdf != null) checkPassword(salt = salt, count = count)
        header.bytes(HeaderNames.PARTY_U)
        header.bytes(HeaderNames.PARTY_V)
        val ephemeralKey = ephemeralKey(header).takeIf { algorithm.isAgreement }
        require(!algorithm.isAgreement || ephemeralKey != null)
        return RecipientParts(
            header = header,
            ephemeralKey = ephemeralKey,
            iv = iv,
            tag = tag,
            salt = salt,
            count = count?.toInt(),
        )
    }

    private fun checkPassword(salt: ByteString?, count: Long?) {
        require(salt != null && salt.size >= MINIMUM_SALT_BYTES && count != null && count >= 1)
        refuseUnless(count <= limits.maximumIterations, JoseFailure.LimitExceeded)
        val policy = crypto.environment.policy
        refuseUnless(policy.permitsIterations(count.toInt(), AlgorithmUse.Verify), JoseFailure.AlgorithmNotAllowed)
    }

    private fun ephemeralKey(header: JsonValue.Object): PublicKey? {
        val json = header.member(HeaderNames.EPHEMERAL_KEY) ?: return null
        val jwk = keys.read(json).orRefuse()
        require(!jwk.isPrivate && jwk.curve?.family in AGREEMENT_FAMILIES)
        return keys.publicKey(jwk).orRefuse()
    }

    private suspend fun wrapped(kek: SecretKey, cek: SecretBytes, wrap: KeyWrapAlgorithm): Wrapped =
        Wrapped(cek = cek, encryptedKey = crypto.keyWraps.wrap(kek = kek, key = cek, algorithm = wrap))

    private suspend fun gcmWrapped(kek: SecretKey, cek: SecretBytes, gcm: AeadAlgorithm): Wrapped {
        val iv = ByteString(crypto.environment.random.bytes(GCM_IV_BYTES))
        val sealed = cek.reveal { bytes ->
            crypto.aead.encrypt(
                key = kek,
                nonce = iv,
                plaintext = ByteString(bytes),
                associatedData = ByteString(),
                algorithm = gcm,
            )
        }
        val split = sealed.size - gcm.tagBytes
        return Wrapped(
            cek = cek,
            encryptedKey = sealed.substring(startIndex = 0, endIndex = split),
            members = listOf(
                HeaderNames.IV to encoded(iv),
                HeaderNames.TAG to encoded(sealed.substring(startIndex = split, endIndex = sealed.size)),
            ),
        )
    }

    private suspend fun agreed(wrapping: Wrapping): Wrapped {
        val recipient = wrapping.recipient
        val encryption = wrapping.encryption
        val cek = wrapping.cek
        val header = wrapping.header
        val publicKey = requireNotNull((recipient.key as? JoseKey.Public)?.key) { "ECDH-ES encrypts to a public key" }
        val type = KeyType.entries.firstOrNull { type ->
            type.family == publicKey.family && type.curve == publicKey.curve && type.family in AGREEMENT_FAMILIES
        }
        requireNotNull(type) { "ECDH-ES needs an EC, X25519 or X448 key" }
        val ephemeral = crypto.keys.generate(type)
        val secret = crypto.agreements.agree(privateKey = ephemeral.privateKey, publicKey = publicKey)
        ephemeral.privateKey.destroy()
        val derived = secret.use { found ->
            derive(algorithm = recipient.algorithm, encryption = encryption, secret = found, header = header)
        }
        val members = listOf(HeaderNames.EPHEMERAL_KEY to JwkWriter.objectOf(keys.of(ephemeral.publicKey)))
        val wrap = recipient.algorithm.wrap ?: return Wrapped(cek = derived, members = members)
        val kek = derived.use { found -> SecretKey.of(found) }
        val result = wrapped(kek = kek, cek = cek, wrap = wrap)
        kek.destroy()
        return Wrapped(cek = result.cek, encryptedKey = result.encryptedKey, members = members)
    }

    private suspend fun rsaWrapped(key: JoseKey, cek: SecretBytes): Wrapped {
        val publicKey = (key as? JoseKey.Public)?.let { found ->
            found.key.takeIf { found.key.family == KeyFamily.Rsa }
        }
        requireNotNull(publicKey) { "RSA-OAEP-256 encrypts to an RSA public key" }
        val encrypted = cek.reveal { bytes ->
            crypto.encryptions.encrypt(publicKey = publicKey, plaintext = ByteString(bytes), algorithm = OAEP)
        }
        return Wrapped(cek = cek, encryptedKey = encrypted)
    }

    private suspend fun passwordWrapped(wrapping: Wrapping): Wrapped {
        val recipient = wrapping.recipient
        val cek = wrapping.cek
        val password = requireNotNull(recipient.key as? JoseKey.Password) { "PBES2 encrypts with a password" }
        val salt = ByteString(crypto.environment.random.bytes(SALT_BYTES))
        val iterations = recipient.iterations ?: crypto.environment.policy.minimumIterations
        val kek = passwordKey(
            algorithm = recipient.algorithm,
            password = password,
            salt = salt,
            iterations = iterations,
            use = AlgorithmUse.Protect,
        )
        val result = wrapped(kek = kek, cek = cek, wrap = wrapOf(recipient.algorithm))
        kek.destroy()
        val members = listOf(
            HeaderNames.SALT to encoded(salt),
            HeaderNames.COUNT to JsonValue.Integer(iterations.toLong()),
        )
        return Wrapped(cek = result.cek, encryptedKey = result.encryptedKey, members = members)
    }

    private fun directBack(attempt: Attempt): Unwrapped? =
        fittingSecret(attempt.key, attempt.encryption.keyBytes)?.let { found -> Unwrapped(found.export()) }

    private suspend fun rsaBack(attempt: Attempt): Unwrapped? = rsaKey(attempt.key)?.let { found ->
        Unwrapped(crypto.encryptions.decrypt(privateKey = found, ciphertext = attempt.encryptedKey, algorithm = OAEP))
    }

    private suspend fun unwrapped(attempt: Attempt): Unwrapped? {
        val wrap = wrapOf(attempt.algorithm)
        val kek = fittingSecret(attempt.key, wrap.keyBytes) ?: return null
        return Unwrapped(crypto.keyWraps.unwrap(kek = kek, wrapped = attempt.encryptedKey, algorithm = wrap))
    }

    private suspend fun gcmUnwrapped(attempt: Attempt): Unwrapped? {
        val gcm = gcmOf(attempt.algorithm)
        val kek = fittingSecret(attempt.key, gcm.keyBytes) ?: return null
        val parts = attempt.parts
        val sealed = attempt.encryptedKey.toByteArray() + invariant(parts.tag).toByteArray()
        val opened = crypto.aead.decrypt(
            key = kek,
            nonce = invariant(parts.iv),
            ciphertext = ByteString(sealed),
            associatedData = ByteString(),
            algorithm = gcm,
        )
        return Unwrapped(opened?.let { bytes -> SecretBytes.copyOf(bytes) })
    }

    private suspend fun agreedBack(attempt: Attempt): Unwrapped? {
        val publicKey = invariant(attempt.parts.ephemeralKey)
        val privateKey = (attempt.key as? JoseKey.Private)?.let { found ->
            found.key.takeIf { isPairOf(found.key, publicKey) }
        }
        return privateKey?.let { found ->
            Unwrapped(agreedKey(attempt = attempt, privateKey = found, publicKey = publicKey))
        }
    }

    private suspend fun agreedKey(attempt: Attempt, privateKey: PrivateKey, publicKey: PublicKey): SecretBytes? {
        val derived = crypto.agreements.agree(privateKey = privateKey, publicKey = publicKey).use { secret ->
            derive(
                algorithm = attempt.algorithm,
                encryption = attempt.encryption,
                secret = secret,
                header = attempt.parts.header,
            )
        }
        val wrap = attempt.algorithm.wrap ?: return derived
        val kek = derived.use { found -> SecretKey.of(found) }
        val cek = crypto.keyWraps.unwrap(kek = kek, wrapped = attempt.encryptedKey, algorithm = wrap)
        kek.destroy()
        return cek
    }

    private suspend fun passwordBack(attempt: Attempt): Unwrapped? {
        val password = attempt.key as? JoseKey.Password ?: return null
        val kek = passwordKey(
            algorithm = attempt.algorithm,
            password = password,
            salt = invariant(attempt.parts.salt),
            iterations = invariant(attempt.parts.count),
            use = AlgorithmUse.Verify,
        )
        val wrap = wrapOf(attempt.algorithm)
        val cek = crypto.keyWraps.unwrap(kek = kek, wrapped = attempt.encryptedKey, algorithm = wrap)
        kek.destroy()
        return Unwrapped(cek)
    }

    private suspend fun passwordKey(
        algorithm: JweAlgorithm,
        password: JoseKey.Password,
        salt: ByteString,
        iterations: Int,
        use: AlgorithmUse,
    ): SecretKey {
        val fullSalt = algorithm.algorithmName.encodeToByteArray() + SEPARATOR + salt.toByteArray()
        val derived = crypto.derivations.pbkdf2(
            password = password.password,
            salt = ByteString(fullSalt),
            iterations = iterations,
            length = wrapOf(algorithm).keyBytes,
            algorithm = invariant(algorithm.kdf),
            use = use,
        )
        return derived.use { found -> SecretKey.of(found) }
    }

    private suspend fun derive(
        algorithm: JweAlgorithm,
        encryption: JweEncryption,
        secret: SecretBytes,
        header: JsonValue.Object,
    ): SecretBytes {
        val (algorithmId, bytes) = algorithm.wrap?.let { wrap -> algorithm.algorithmName to wrap.keyBytes }
            ?: (encryption.algorithmName to encryption.keyBytes)
        return ConcatKdf.derive(
            crypto = crypto,
            secret = secret,
            algorithmId = algorithmId,
            partyU = header.bytes(HeaderNames.PARTY_U) ?: ByteString(),
            partyV = header.bytes(HeaderNames.PARTY_V) ?: ByteString(),
            bits = bytes * BYTE_BITS,
        )
    }

    private fun secretOf(key: JoseKey, bytes: Int): SecretKey =
        requireNotNull(fittingSecret(key, bytes)) { "The algorithm needs a symmetric key of $bytes bytes" }

    private fun secretOf(key: JoseKey, algorithm: JweAlgorithm): SecretKey {
        val bytes = algorithm.wrap?.keyBytes ?: gcmOf(algorithm).keyBytes
        return secretOf(key, bytes)
    }

    private fun wrapOf(algorithm: JweAlgorithm): KeyWrapAlgorithm = invariant(algorithm.wrap)

    private fun gcmOf(algorithm: JweAlgorithm): AeadAlgorithm = invariant(algorithm.gcm)

    private companion object {
        val OAEP: AsymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm.RsaOaepSha256
        val AGREEMENT_FAMILIES: Set<KeyFamily> = setOf(KeyFamily.Ec, KeyFamily.X25519, KeyFamily.X448)
    }
}
