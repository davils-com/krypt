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

package com.davils.krypt.stream.internal

import com.davils.kore.core.failure.attempted
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.cipher.SealedBox
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.stream.Credential
import com.davils.krypt.stream.Recipient
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.internal.StreamRefusal.Companion.ensure
import kotlinx.io.bytestring.ByteString

private const val KEY: Int = 1
private const val HYBRID: Int = 2
private const val SERVICE: Int = 3
private const val PASSWORD: Int = 4
private const val SALT_BYTES: Int = 16
private const val ITERATION_BYTES: Int = 4
private const val KEK_BYTES: Int = 32

internal class Wrapping(private val crypto: Crypto, private val limits: StreamLimits) {
    suspend fun wrap(recipient: Recipient, dataKey: SecretBytes, context: ByteString): RecipientEntry =
        when (recipient) {
            is Recipient.Key -> RecipientEntry(
                kind = KEY,
                label = ByteString(),
                wrapped = recipient.aead.encrypt(plaintext = plaintextOf(dataKey), associatedData = context),
            )

            is Recipient.Hybrid -> RecipientEntry(
                kind = HYBRID,
                label = ByteString(),
                wrapped = recipient.encrypter.encrypt(plaintext = plaintextOf(dataKey), associatedData = context),
            )

            is Recipient.Service -> RecipientEntry(
                kind = SERVICE,
                label = Octets.utf8(recipient.kms.keyUri),
                wrapped = recipient.kms.encrypt(plaintext = dataKey, associatedData = context),
            )

            is Recipient.Password -> password(
                recipient = recipient,
                plaintext = plaintextOf(dataKey),
                context = context,
            )
        }

    fun passwords(entries: List<RecipientEntry>): Int = entries.count { entry -> entry.kind == PASSWORD }

    fun candidates(credential: Credential, entries: List<RecipientEntry>): List<RecipientEntry> = when (credential) {
        is Credential.Key -> entries.filter { entry -> entry.kind == KEY }
        is Credential.Hybrid -> entries.filter { entry -> entry.kind == HYBRID }
        is Credential.Service -> firstNaming(credential, entries)
        is Credential.Password -> entries.filter { entry -> entry.kind == PASSWORD }
    }

    suspend fun unwrap(credential: Credential, entry: RecipientEntry, context: ByteString): SecretBytes? {
        val wrapped = entry.wrapped
        val opened = when (credential) {
            is Credential.Key -> credential.aead.decrypt(ciphertext = wrapped, associatedData = context)
            is Credential.Hybrid -> credential.decrypter.decrypt(ciphertext = wrapped, associatedData = context)
            is Credential.Service -> return serviceOf(credential = credential, wrapped = wrapped, context = context)
            is Credential.Password -> openPassword(password = credential, entry = entry, context = context)
        }
        return opened?.let { bytes -> SecretBytes.copyOf(bytes) }
    }

    private fun firstNaming(credential: Credential.Service, entries: List<RecipientEntry>): List<RecipientEntry> {
        val label = Octets.utf8(credential.kms.keyUri)
        val naming = entries.filter { entry -> entry.kind == SERVICE && entry.label == label }
        return naming.take(1)
    }

    private suspend fun serviceOf(
        credential: Credential.Service,
        wrapped: ByteString,
        context: ByteString,
    ): SecretBytes? {
        val opened = attempted { credential.kms.decrypt(ciphertext = wrapped, associatedData = context) }
        return opened.getOrNull()
    }

    private fun plaintextOf(dataKey: SecretBytes): ByteString = dataKey.reveal { bytes -> ByteString(bytes) }

    private suspend fun password(
        recipient: Recipient.Password,
        plaintext: ByteString,
        context: ByteString,
    ): RecipientEntry {
        val salt = ByteString(crypto.environment.random.bytes(SALT_BYTES))
        val kek = crypto.derivations.pbkdf2(
            password = recipient.password,
            salt = salt,
            iterations = recipient.iterations,
            length = KEK_BYTES,
        )
        val key = SecretKey.of(kek)
        val box = crypto.aead.seal(key = key, plaintext = plaintext, associatedData = context)
        key.destroy()
        return RecipientEntry(
            kind = PASSWORD,
            label = Octets.concat(salt, Octets.u32(recipient.iterations.toLong())),
            wrapped = box.encoded,
        )
    }

    private suspend fun openPassword(
        password: Credential.Password,
        entry: RecipientEntry,
        context: ByteString,
    ): ByteString? {
        val label = entry.label.toByteArray()
        ensure(label.size == SALT_BYTES + ITERATION_BYTES, StreamFailure.Malformed)
        val iterations = Octets.unsigned(bytes = label, offset = SALT_BYTES, count = ITERATION_BYTES)
        val isPermitted = iterations <= limits.maximumIterations &&
            crypto.environment.policy.permitsIterations(iterations.toInt(), AlgorithmUse.Verify)
        ensure(isPermitted, StreamFailure.Refused)
        val kek = crypto.derivations.pbkdf2(
            password = password.password,
            salt = ByteString(data = label, startIndex = 0, endIndex = SALT_BYTES),
            iterations = iterations.toInt(),
            length = KEK_BYTES,
            use = AlgorithmUse.Verify,
        )
        val key = SecretKey.of(kek)
        val box = SealedBox.decodeOrNull(entry.wrapped, AeadAlgorithm.Aes256Gcm)
        val opened = box?.let { found -> crypto.aead.open(key = key, box = found, associatedData = context) }
        key.destroy()
        return opened
    }
}
