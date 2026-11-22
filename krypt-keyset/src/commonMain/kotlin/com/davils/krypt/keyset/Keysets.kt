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

package com.davils.krypt.keyset

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.telemetry.AuditTrail
import com.davils.krypt.core.telemetry.EventSink
import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.keyset.internal.KeyFactory
import com.davils.krypt.keyset.internal.KeysetCodec
import com.davils.krypt.keyset.kms.KeyManagementService
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.coroutines.flow.Flow
import kotlinx.io.bytestring.ByteString

private const val DEFAULT_DERIVED_BYTES: Int = 32
private const val DERIVE_LABEL: String = "krypt keyset derive v1 "
private const val ENCRYPT_LABEL: String = "krypt keyset v1 "

/**
 * Creates, changes, stores and uses [Keyset]s with the primitives of [crypto].
 *
 * Every change returns a new key set and leaves the given one as it is, with one exception: [destroy] wipes the
 * material of a key in every key set that holds it. Every change is recorded in the audit trail of the environment
 * first and sent as a [KeysetEvent]; a required audit that cannot record it refuses the change with an
 * [com.davils.krypt.core.audit.AuditRefusedException] and changes nothing.
 *
 * The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their environment.
 * @property limits the limits of key sets.
 * @since 1.0.0
 */
public class Keysets(public val crypto: Crypto, public val limits: KeysetLimits = KeysetLimits.Default) {
    private val sink = EventSink(crypto.environment, KeysetEvent.TOPIC)
    private val trail = AuditTrail(crypto.environment)

    /**
     * The events of every change, hot and without replay.
     *
     * @since 1.0.0
     */
    public val events: Flow<KeysetEvent> get() = sink.events

    /**
     * Generates a key set of [purpose] with one key, its primary key.
     *
     * @param purpose what the keys are for.
     * @return the key set.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the algorithm of [purpose].
     * @throws com.davils.krypt.primitive.UnsupportedAlgorithmException if the platform lacks it.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun generate(purpose: KeyPurpose): Keyset {
        val key = KeyFactory.generate(crypto, purpose)
        record(action = KeysetAction.Generated, key = key, purpose = purpose)
        return Keyset(purpose = purpose, keys = listOf(key), primaryId = key.id)
    }

    /**
     * Adds a new key to [keyset] and makes it the primary key; the former primary key stays enabled, so what it
     * protected can still be opened.
     *
     * @param keyset the key set.
     * @return the rotated key set.
     * @throws IllegalArgumentException if [keyset] is public or full.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun rotate(keyset: Keyset): Keyset {
        val key = newKey(keyset, KeysetAction.Rotated)
        return Keyset(purpose = keyset.purpose, keys = keyset.keys + key, primaryId = key.id)
    }

    /**
     * Adds a new enabled key to [keyset] beside the primary key, so that every reader knows it before it is
     * [promote]d: the safe way to rotate keys that several services share.
     *
     * @param keyset the key set.
     * @return the key set with the new key.
     * @throws IllegalArgumentException if [keyset] is public or full.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun add(keyset: Keyset): Keyset {
        val key = newKey(keyset, KeysetAction.Added)
        return Keyset(purpose = keyset.purpose, keys = keyset.keys + key, primaryId = keyset.primaryId)
    }

    /**
     * Makes the enabled key [id] the primary key.
     *
     * @param keyset the key set.
     * @param id the key.
     * @return the key set with the new primary key.
     * @throws IllegalArgumentException if [keyset] has no enabled key [id].
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun promote(keyset: Keyset, id: KeyId): Keyset {
        val key = keyset.keyOf(id)
        require(key.isUsable) { "Only an enabled key becomes the primary key" }
        record(action = KeysetAction.Promoted, key = key, purpose = keyset.purpose)
        return Keyset(purpose = keyset.purpose, keys = keyset.keys, primaryId = id)
    }

    /**
     * Enables the disabled key [id] again.
     *
     * @param keyset the key set.
     * @param id the key.
     * @return the key set with the key enabled.
     * @throws IllegalArgumentException if [keyset] has no disabled key [id].
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun enable(keyset: Keyset, id: KeyId): Keyset {
        val key = keyset.keyOf(id)
        require(key.status == KeyStatus.Disabled) { "Only a disabled key is enabled" }
        return change(keyset = keyset, key = key, status = KeyStatus.Enabled, action = KeysetAction.Enabled)
    }

    /**
     * Disables the key [id], which then opens and verifies nothing until it is enabled again.
     *
     * @param keyset the key set.
     * @param id the key, not the primary key.
     * @return the key set with the key disabled.
     * @throws IllegalArgumentException if [keyset] has no enabled key [id] or [id] is the primary key.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun disable(keyset: Keyset, id: KeyId): Keyset {
        val key = keyset.keyOf(id)
        require(key.status == KeyStatus.Enabled && id != keyset.primaryId) {
            "Only an enabled key that is not the primary key is disabled"
        }
        return change(keyset = keyset, key = key, status = KeyStatus.Disabled, action = KeysetAction.Disabled)
    }

    /**
     * Destroys the key [id]: its material is wiped in every key set that holds it and only its id is kept, so that
     * nothing it protected can be opened again. This is how data is shredded by crypto.
     *
     * @param keyset the key set.
     * @param id the key, not the primary key.
     * @return the key set with the key destroyed.
     * @throws IllegalArgumentException if [keyset] has no key [id] that is not destroyed, or [id] is the primary key.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the change.
     * @since 1.0.0
     */
    public suspend fun destroy(keyset: Keyset, id: KeyId): Keyset {
        val key = keyset.keyOf(id)
        require(key.status != KeyStatus.Destroyed && id != keyset.primaryId) {
            "Only a key that is not destroyed and not the primary key is destroyed"
        }
        record(action = KeysetAction.Destroyed, key = key, purpose = keyset.purpose)
        key.secret?.destroy()
        key.privateKey?.destroy()
        return keyset.replaced(key.destroyed())
    }

    /**
     * Removes the destroyed keys from [keyset], once their ids are no longer needed to tell why data cannot be opened.
     *
     * @param keyset the key set.
     * @return the key set without destroyed keys.
     * @since 1.0.0
     */
    public fun prune(keyset: Keyset): Keyset {
        val kept = keyset.keys.filter { key -> key.status != KeyStatus.Destroyed }
        return Keyset(purpose = keyset.purpose, keys = kept, primaryId = keyset.primaryId)
    }

    /**
     * Returns the public part of an asymmetric [keyset], which verifies signatures and encrypts but holds no secret.
     *
     * @param keyset the key set of a signing or hybrid purpose.
     * @return the public key set.
     * @throws IllegalArgumentException if [keyset] holds symmetric keys.
     * @since 1.0.0
     */
    public fun publicKeyset(keyset: Keyset): Keyset {
        requireNotNull(keyset.purpose.keyType) { "A key set of symmetric keys has no public part" }
        val keys = keyset.keys.map { key -> key.publicOnly() }
        return Keyset(purpose = keyset.purpose, keys = keys, primaryId = keyset.primaryId)
    }

    /**
     * Returns the authenticated encryption of [keyset].
     *
     * @param keyset a key set of [KeyPurpose.Aead].
     * @return the encryption.
     * @throws IllegalArgumentException if [keyset] has another purpose.
     * @since 1.0.0
     */
    public fun aead(keyset: Keyset): KeysetAead {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Aead) { "A key set of $purpose does not encrypt" }
        return KeysetAead(crypto = crypto, keyset = keyset, algorithm = purpose.algorithm)
    }

    /**
     * Returns the message authentication of [keyset].
     *
     * @param keyset a key set of [KeyPurpose.Mac].
     * @return the authentication.
     * @throws IllegalArgumentException if [keyset] has another purpose.
     * @since 1.0.0
     */
    public fun mac(keyset: Keyset): KeysetMac {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Mac) { "A key set of $purpose does not authenticate" }
        return KeysetMac(crypto = crypto, keyset = keyset, algorithm = purpose.algorithm)
    }

    /**
     * Returns the signer of [keyset], which signs with its primary key.
     *
     * @param keyset a private key set of [KeyPurpose.Signing].
     * @return the signer.
     * @throws IllegalArgumentException if [keyset] has another purpose or is public.
     * @since 1.0.0
     */
    public fun signer(keyset: Keyset): KeysetSigner {
        require(keyset.purpose is KeyPurpose.Signing && !keyset.isPublic) { "Only a private signing key set signs" }
        return KeysetSigner(crypto = crypto, keyset = keyset)
    }

    /**
     * Returns the verifier of [keyset], private or public.
     *
     * @param keyset a key set of [KeyPurpose.Signing].
     * @return the verifier.
     * @throws IllegalArgumentException if [keyset] has another purpose.
     * @since 1.0.0
     */
    public fun verifier(keyset: Keyset): KeysetVerifier {
        require(keyset.purpose is KeyPurpose.Signing) { "Only a signing key set verifies" }
        return KeysetVerifier(crypto = crypto, keyset = keyset)
    }

    /**
     * Returns the hybrid encryption to the primary key of [keyset], private or public.
     *
     * @param keyset a key set of [KeyPurpose.Hybrid].
     * @return the encryption.
     * @throws IllegalArgumentException if [keyset] has another purpose.
     * @since 1.0.0
     */
    public fun encrypter(keyset: Keyset): HybridEncrypter {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Hybrid) { "A key set of $purpose does not encrypt to public keys" }
        return HybridEncrypter(crypto = crypto, keyset = keyset, suite = purpose.suite)
    }

    /**
     * Returns the hybrid decryption of [keyset].
     *
     * @param keyset a private key set of [KeyPurpose.Hybrid].
     * @return the decryption.
     * @throws IllegalArgumentException if [keyset] has another purpose or is public.
     * @since 1.0.0
     */
    public fun decrypter(keyset: Keyset): HybridDecrypter {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Hybrid && !keyset.isPublic) { "Only a private hybrid key set decrypts" }
        return HybridDecrypter(crypto = crypto, keyset = keyset, suite = purpose.suite)
    }

    /**
     * Derives a key for [context] from the key [id] of a symmetric [keyset] with HKDF, so that one key set serves
     * many purposes, such as one key per tenant or per table, without storing each key.
     *
     * The same key and context always derive the same key; different contexts derive independent keys.
     *
     * @param keyset a key set of [KeyPurpose.Aead] or [KeyPurpose.Mac].
     * @param context what the key is for, such as `tenant/42/records`.
     * @param size the size of the derived key in bytes, 16 to 64; 32 by default.
     * @param id the key to derive from; the primary key by default.
     * @return the derived key.
     * @throws IllegalArgumentException if [keyset] is asymmetric, has no enabled key [id] or [size] is out of range.
     * @since 1.0.0
     */
    public suspend fun derive(
        keyset: Keyset,
        context: ByteString,
        size: Int = DEFAULT_DERIVED_BYTES,
        id: KeyId = keyset.primaryId,
    ): SecretKey {
        require(size in SecretKey.MINIMUM_BYTES..MAXIMUM_DERIVED_BYTES) {
            "A derived key has ${SecretKey.MINIMUM_BYTES} to $MAXIMUM_DERIVED_BYTES bytes"
        }
        val key = keyset.keyOf(id)
        val usable = key.secret?.takeIf { key.isUsable }
        val secret = requireNotNull(usable) { "Only an enabled symmetric key derives keys" }
        val info = Bytes.concat(Bytes.utf8(DERIVE_LABEL), context)
        val derived = secret.export().use { material ->
            crypto.derivations.hkdf(inputKey = material, salt = id.bytes, info = info, length = size)
        }
        return SecretKey.of(derived)
    }

    /**
     * Encrypts [keyset] with [kms], so that it can be stored outside the process.
     *
     * The result names the key of [kms] and binds [associatedData], such as the name the key set is stored under, so
     * that a key set moved to another name is refused when it is decrypted.
     *
     * @param keyset the key set; every private key must be extractable.
     * @param kms the key management service that holds the key encryption key.
     * @param associatedData authenticated context; empty by default.
     * @return the encrypted key set.
     * @throws IllegalStateException if a private key is not extractable or was destroyed.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        keyset: Keyset,
        kms: KeyManagementService,
        associatedData: ByteString = ByteString(),
    ): ByteString {
        val plaintext = KeysetCodec.encode(crypto, keyset)
        val context = Bytes.concat(Bytes.utf8(ENCRYPT_LABEL), associatedData)
        val ciphertext = SecretBytes.copyOf(plaintext).use { secret -> kms.encrypt(secret, context) }
        return KeysetCodec.encodeEncrypted(keyUri = kms.keyUri, ciphertext = ciphertext)
    }

    /**
     * Decrypts a key set that [encrypt] encrypted with the same [kms] and [associatedData].
     *
     * @param encrypted the encrypted key set.
     * @param kms the key management service.
     * @param associatedData the authenticated context it was encrypted with.
     * @return the key set, or why it could not be read, [KeysetFailure.Unavailable] if [kms] threw; a cancellation
     *   of the caller passes on.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        encrypted: ByteString,
        kms: KeyManagementService,
        associatedData: ByteString = ByteString(),
    ): Outcome<Keyset, KeysetFailure> {
        val parsed = KeysetCodec.decodeEncryptedOrNull(encrypted, limits)
            ?: return Outcome.Failure(KeysetFailure.Malformed)
        val context = Bytes.concat(Bytes.utf8(ENCRYPT_LABEL), associatedData)
        return when (parsed.first == kms.keyUri) {
            false -> Outcome.Failure(KeysetFailure.WrongKeyManagementService)
            true -> openWith(kms = kms, ciphertext = parsed.second, context = context)
        }
    }

    /**
     * Encodes a public [keyset], to hand it to those who verify or encrypt.
     *
     * @param keyset the public key set.
     * @return the encoding.
     * @throws IllegalArgumentException if [keyset] is not public.
     * @since 1.0.0
     */
    public fun encodePublic(keyset: Keyset): ByteString {
        require(keyset.isPublic) { "Only a public key set is encoded in the clear" }
        return KeysetCodec.encode(crypto, keyset)
    }

    /**
     * Decodes a public key set that [encodePublic] encoded.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the public key set, or why it could not be read.
     * @since 1.0.0
     */
    public suspend fun decodePublic(encoded: ByteString): Outcome<Keyset, KeysetFailure> =
        KeysetCodec.decode(crypto = crypto, encoded = encoded, limits = limits, isPublic = true)

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Keysets($limits)"

    private suspend fun openWith(
        kms: KeyManagementService,
        ciphertext: ByteString,
        context: ByteString,
    ): Outcome<Keyset, KeysetFailure> {
        val opened = attempted { kms.decrypt(ciphertext, context) }
        return opened.fold(
            onSuccess = { plaintext ->
                val bytes = plaintext?.use { secret -> secret.reveal { revealed -> ByteString(revealed) } }
                bytes?.let { encoded ->
                    KeysetCodec.decode(crypto = crypto, encoded = encoded, limits = limits, isPublic = false)
                } ?: Outcome.Failure(KeysetFailure.DecryptionFailed)
            },
            onFailure = { _ -> Outcome.Failure(KeysetFailure.Unavailable) },
        )
    }

    private suspend fun newKey(keyset: Keyset, action: KeysetAction): KeysetKey {
        require(!keyset.isPublic) { "A public key set gets no new keys" }
        require(keyset.keys.size < limits.maximumKeys) {
            "A key set holds at most ${limits.maximumKeys} keys; prune destroyed keys first"
        }
        val key = KeyFactory.generate(crypto, keyset.purpose)
        record(action = action, key = key, purpose = keyset.purpose)
        return key
    }

    private suspend fun change(keyset: Keyset, key: KeysetKey, status: KeyStatus, action: KeysetAction): Keyset {
        record(action = action, key = key, purpose = keyset.purpose)
        return keyset.replaced(key.withStatus(status))
    }

    private suspend fun record(action: KeysetAction, key: KeysetKey, purpose: KeyPurpose) {
        trail.require(action = action.audit, subject = key.id.hex, attributes = mapOf(PURPOSE to purpose.toString()))
        sink.emit { KeysetEvent(action = action, keyId = key.id) }
    }

    private companion object {
        const val PURPOSE: String = "purpose"
        const val MAXIMUM_DERIVED_BYTES: Int = 64
    }
}
