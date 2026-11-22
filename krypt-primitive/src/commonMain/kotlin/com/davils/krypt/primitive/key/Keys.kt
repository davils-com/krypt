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

package com.davils.krypt.primitive.key

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.core.outcome.mapFailure
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.asn1.pem.PemBlock
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.internal.KeyCodec
import com.davils.krypt.primitive.internal.KeyProbes
import com.davils.krypt.primitive.internal.KeyShape
import com.davils.krypt.primitive.internal.Pbes2
import com.davils.krypt.primitive.internal.PemKeys
import kotlinx.io.bytestring.ByteString

private const val DEFAULT_SECRET_BYTES: Int = 32

/**
 * Generating keys and reading and writing them: SubjectPublicKeyInfo, PKCS #8, encrypted PKCS #8 with PBES2, the
 * PKCS #1 and SEC1 forms of OpenSSL, and their PEM.
 *
 * Every key krypt reads is checked against the policy: an RSA key below the size the policy verifies, or a key on a
 * curve it does not permit, is refused. Encrypted keys are read with a bounded number of PBKDF2 iterations, so a
 * crafted file cannot demand unbounded work.
 *
 * @since 1.0.0
 */
public class Keys internal constructor(private val crypto: Crypto) {
    /**
     * Generates a key pair of [type].
     *
     * @param type the key type.
     * @return the key pair, whose private key is extractable.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the size or the curve.
     * @throws UnsupportedAlgorithmException if the platform cannot generate [type].
     * @since 1.0.0
     */
    public suspend fun generate(type: KeyType): KeyPair {
        crypto.permitKey(type, AlgorithmUse.Protect)
        if (!crypto.capabilities.supports(type)) throw UnsupportedAlgorithmException(type.name)
        return crypto.backend.generate(type)
    }

    /**
     * Generates a symmetric key of [size] random bytes.
     *
     * @param size the number of bytes, at least 16; 32 by default, for AES-256 and HMAC-SHA-256.
     * @return the key.
     * @throws IllegalArgumentException if [size] is below 16.
     * @since 1.0.0
     */
    public fun generateSecret(size: Int = DEFAULT_SECRET_BYTES): SecretKey {
        require(size >= SecretKey.MINIMUM_BYTES) { "A symmetric key has at least ${SecretKey.MINIMUM_BYTES} bytes" }
        return SecretKey(SecretBytes.random(size = size, random = crypto.environment.random))
    }

    /**
     * Pairs [privateKey] with [publicKey] after proving that they belong together: by signing and verifying a probe
     * for a signing key, by agreeing with a fresh ephemeral key for a key agreement key and by encapsulating to and
     * decapsulating with the pair for an ML-KEM key.
     *
     * @param privateKey the private key, whose own public key may be unknown, as in a PKCS #8 file of X25519.
     * @param publicKey the public key that should belong to it.
     * @return the pair, whose private key now knows its public key, or null if the keys do not belong together.
     * @throws IllegalArgumentException if the keys are of different families or curves.
     * @since 1.0.0
     */
    public suspend fun pair(privateKey: PrivateKey, publicKey: PublicKey): KeyPair? {
        require(
            privateKey.family == publicKey.family && privateKey.curve == publicKey.curve,
        ) { "The keys are of different kinds" }
        val paired = privateKey.withPublic(publicKey)
        val isMatching = KeyProbes.matches(crypto = crypto, privateKey = paired, publicKey = publicKey)
        return KeyPair(publicKey = publicKey, privateKey = paired).takeIf { isMatching }
    }

    /**
     * Reads a SubjectPublicKeyInfo.
     *
     * @param encoded the DER encoding.
     * @return the key, or why it was refused.
     * @since 1.0.0
     */
    public fun decodePublic(encoded: ByteString): Outcome<PublicKey, KeyFailure> =
        KeyCodec.publicKeyOf(encoded).flatMap { key ->
            permitted(key = key, shape = KeyShape(family = key.family, bits = key.bits, curve = key.curve))
        }

    /**
     * Reads a PKCS #8 PrivateKeyInfo or OneAsymmetricKey.
     *
     * @param encoded the DER encoding, which the key copies; the caller still owns it.
     * @return the key, or why it was refused.
     * @since 1.0.0
     */
    public fun decodePrivate(encoded: SecretBytes): Outcome<PrivateKey, KeyFailure> =
        KeyCodec.privateKeyOf(encoded).flatMap { key ->
            permitted(key = key, shape = KeyShape(family = key.family, bits = key.bits, curve = key.curve))
        }

    /**
     * Returns the PKCS #8 encoding of [key].
     *
     * @param key an extractable private key.
     * @return a copy of the encoding, which the caller owns and should destroy.
     * @throws IllegalStateException if the key is not extractable or was destroyed.
     * @since 1.0.0
     */
    public fun encodePrivate(key: PrivateKey): SecretBytes {
        val encoding = checkNotNull(key.encodingOrNull()) { "The private key is not extractable or was destroyed" }
        return encoding.copy()
    }

    /**
     * Encrypts [key] as an EncryptedPrivateKeyInfo with PBES2: PBKDF2 with HMAC-SHA-256 and AES-256-CBC.
     *
     * @param key an extractable private key.
     * @param password the password.
     * @param iterations the PBKDF2 iterations; the minimum of the policy by default.
     * @return the DER encoding.
     * @throws IllegalStateException if the key is not extractable or was destroyed.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the iterations.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        key: PrivateKey,
        password: SecretText,
        iterations: Int = crypto.environment.policy.minimumIterations,
    ): ByteString = encodePrivate(key).use { encoding ->
        Pbes2.encrypt(crypto = crypto, plaintext = encoding, password = password, iterations = iterations)
    }

    /**
     * Decrypts an EncryptedPrivateKeyInfo.
     *
     * @param encrypted the DER encoding.
     * @param password the password.
     * @return the key, or why it was refused; a wrong password and a tampered file both give
     *   [KeyFailure.WrongPassword].
     * @since 1.0.0
     */
    public suspend fun decrypt(encrypted: ByteString, password: SecretText): Outcome<PrivateKey, KeyFailure> =
        Pbes2.decrypt(crypto = crypto, encoded = encrypted, password = password).flatMap { decrypted ->
            decrypted.use { encoding -> decodeDecrypted(encoding) }
        }

    /**
     * Reads the first public key of a PEM text: `PUBLIC KEY` or `RSA PUBLIC KEY`.
     *
     * @param text the PEM text.
     * @return the key, or why it was refused; [KeyFailure.Malformed] if the text holds no public key.
     * @since 1.0.0
     */
    public fun decodePublicPem(text: String): Outcome<PublicKey, KeyFailure> {
        val decoded = Pem.decode(text).getOrNull()
        val blocks = decoded.orEmpty()
        val spki = blocks.firstNotNullOfOrNull { block ->
            spkiOf(
                block,
            )
        } ?: return Outcome.Failure(KeyFailure.Malformed)
        return decodePublic(spki)
    }

    /**
     * Reads the first private key of a PEM text: `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, or the `RSA PRIVATE KEY` and
     * `EC PRIVATE KEY` forms of OpenSSL. The legacy PEM encryption of OpenSSL is refused.
     *
     * @param text the PEM text.
     * @param password the password of an encrypted key, or null.
     * @return the key, or why it was refused.
     * @since 1.0.0
     */
    public suspend fun decodePrivatePem(text: String, password: SecretText? = null): Outcome<PrivateKey, KeyFailure> {
        val decoded = Pem.decode(text).getOrNull()
        val blocks = decoded.orEmpty()
        val block = blocks.firstOrNull { candidate -> candidate.label in PRIVATE_LABELS } ?: return Outcome.Failure(
            KeyFailure.Malformed,
        )
        return decodePrivateBlock(block = block, password = password)
    }

    /**
     * Writes [key] as PEM `PUBLIC KEY`.
     *
     * @param key the public key.
     * @return the PEM text.
     * @since 1.0.0
     */
    public fun encodePem(key: PublicKey): String = Pem.encode(label = PemKeys.PUBLIC_KEY, bytes = key.encoded)

    /**
     * Writes [key] as unencrypted PEM `PRIVATE KEY`. The text holds the key in the clear; prefer [encryptPem].
     *
     * @param key an extractable private key.
     * @return the PEM text.
     * @throws IllegalStateException if the key is not extractable or was destroyed.
     * @since 1.0.0
     */
    public fun encodePem(key: PrivateKey): String = encodePrivate(key).use { encoding ->
        encoding.reveal { bytes -> Pem.encode(label = PemKeys.PRIVATE_KEY, bytes = ByteString(bytes)) }
    }

    /**
     * Writes [key] encrypted as PEM `ENCRYPTED PRIVATE KEY`; see [encrypt].
     *
     * @param key an extractable private key.
     * @param password the password.
     * @param iterations the PBKDF2 iterations; the minimum of the policy by default.
     * @return the PEM text.
     * @throws IllegalStateException if the key is not extractable or was destroyed.
     * @since 1.0.0
     */
    public suspend fun encryptPem(
        key: PrivateKey,
        password: SecretText,
        iterations: Int = crypto.environment.policy.minimumIterations,
    ): String = Pem.encode(
        label = PemKeys.ENCRYPTED_PRIVATE_KEY,
        bytes = encrypt(key = key, password = password, iterations = iterations),
    )

    /**
     * Computes the fingerprint of [key]: the digest of its SubjectPublicKeyInfo, as certificate pins use it.
     *
     * @param key the public key.
     * @param algorithm the digest; [DigestAlgorithm.Sha256] by default.
     * @return the fingerprint.
     * @since 1.0.0
     */
    public suspend fun fingerprint(key: PublicKey, algorithm: DigestAlgorithm = DigestAlgorithm.Sha256): ByteString =
        crypto.digests.digest(data = key.encoded, algorithm = algorithm)

    private suspend fun decodePrivateBlock(block: PemBlock, password: SecretText?): Outcome<PrivateKey, KeyFailure> {
        if (PemKeys.isLegacyEncrypted(block.headers)) return Outcome.Failure(KeyFailure.UnsupportedEncryption)
        return when (block.label == PemKeys.ENCRYPTED_PRIVATE_KEY) {
            true -> decodeEncrypted(block = block, password = password)
            false -> decodePlain(block)
        }
    }

    private suspend fun decodeEncrypted(block: PemBlock, password: SecretText?): Outcome<PrivateKey, KeyFailure> {
        val found = password ?: return Outcome.Failure(KeyFailure.PasswordRequired)
        return decrypt(encrypted = block.bytes, password = found)
    }

    private fun decodePlain(block: PemBlock): Outcome<PrivateKey, KeyFailure> {
        val converter = PKCS8_CONVERTERS[block.label] ?: { bytes -> bytes }
        val pkcs8 = converter(block.bytes) ?: return Outcome.Failure(KeyFailure.Malformed)
        return SecretBytes.copyOf(pkcs8).use { encoding -> decodePrivate(encoding) }
    }

    private fun decodeDecrypted(encoding: SecretBytes): Outcome<PrivateKey, KeyFailure> = decodePrivate(
        encoding,
    ).mapFailure { failure ->
        listOf(
            failure,
            KeyFailure.WrongPassword,
        )[(failure == KeyFailure.Malformed).compareTo(false)]
    }

    private fun spkiOf(block: PemBlock): ByteString? = SPKI_CONVERTERS[block.label]?.invoke(block.bytes)

    private fun <T> permitted(key: T, shape: KeyShape): Outcome<T, KeyFailure> {
        val isPermitted = crypto.isPermitted(shape, AlgorithmUse.Verify)
        return Outcome.Success(key).takeIf { isPermitted } ?: Outcome.Failure(KeyFailure.Refused)
    }

    private companion object {
        val PKCS8_CONVERTERS: Map<String, (ByteString) -> ByteString?> = mapOf(
            PemKeys.RSA_PRIVATE_KEY to { bytes -> PemKeys.pkcs8OfPkcs1(bytes) },
            PemKeys.EC_PRIVATE_KEY to { bytes -> PemKeys.pkcs8OfSec1(bytes) },
        )

        val SPKI_CONVERTERS: Map<String, (ByteString) -> ByteString> = mapOf(
            PemKeys.PUBLIC_KEY to { bytes -> bytes },
            PemKeys.RSA_PUBLIC_KEY to { bytes -> PemKeys.spkiOfPkcs1(bytes) },
        )

        val PRIVATE_LABELS: Set<String> = setOf(
            PemKeys.PRIVATE_KEY,
            PemKeys.ENCRYPTED_PRIVATE_KEY,
            PemKeys.RSA_PRIVATE_KEY,
            PemKeys.EC_PRIVATE_KEY,
        )
    }
}
