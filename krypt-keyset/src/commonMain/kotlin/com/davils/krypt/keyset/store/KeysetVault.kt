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

package com.davils.krypt.keyset.store

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.telemetry.AuditTrail
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.keyset.kms.KeyManagementService

private const val MAXIMUM_NAME_LENGTH: Int = 256
private const val DEFAULT_ATTEMPTS: Int = 3
private const val MAXIMUM_ATTEMPTS: Int = 16
private const val FIRST_PRINTABLE: Char = ' '
private const val LAST_PRINTABLE: Char = '~'
private val DELETE: AuditAction = AuditAction("keyset.delete")

/**
 * Keeps named key sets in a [repository], encrypted by [kms] and bound to their names, and changes them safely under
 * concurrency.
 *
 * Every key set is encrypted with its name as associated data, so a key set copied under another name is refused.
 * [update] reads, changes and stores with the revision of the repository and tries again when another process changed
 * the key set in between.
 *
 * @property keysets the key sets and their primitives.
 * @param repository where the encrypted key sets are kept.
 * @param kms the service that encrypts them.
 * @property attempts how often [update] tries when another process changes the same key set; 1 to 16, 3 by default.
 * @constructor Keeps key sets in [repository].
 * @throws IllegalArgumentException if [attempts] is out of range.
 * @since 1.0.0
 */
public class KeysetVault(
    public val keysets: Keysets,
    private val repository: KeysetRepository,
    private val kms: KeyManagementService,
    public val attempts: Int = DEFAULT_ATTEMPTS,
) {
    private val trail = AuditTrail(keysets.crypto.environment)

    init {
        require(attempts in 1..MAXIMUM_ATTEMPTS) { "A vault tries 1 to $MAXIMUM_ATTEMPTS times" }
    }

    /**
     * Generates a key set of [purpose] and stores it under [name].
     *
     * @param name the name: 1 to 256 printable ASCII characters.
     * @param purpose what the keys are for.
     * @return the key set, or [KeysetFailure.Conflict] if a key set is stored under [name] already.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun create(name: String, purpose: KeyPurpose): Outcome<Keyset, KeysetFailure> {
        checkName(name)
        val keyset = keysets.generate(purpose)
        val isStored = repository.store(
            name = name,
            keyset = storedOf(name, keyset, revision = 1L),
            expectedRevision = null,
        )
        return when (isStored) {
            true -> Outcome.Success(keyset)
            false -> Outcome.Failure(KeysetFailure.Conflict)
        }
    }

    /**
     * Loads and decrypts the key set stored under [name].
     *
     * @param name the name.
     * @return the key set, or why it could not be read, [KeysetFailure.Missing] if none is stored under [name].
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun load(name: String): Outcome<Keyset, KeysetFailure> {
        checkName(name)
        val stored = repository.load(name) ?: return Outcome.Failure(KeysetFailure.Missing)
        return decrypt(name, stored)
    }

    /**
     * Changes the key set stored under [name] with [change], such as `keysets::rotate`, and stores the result.
     *
     * @param name the name.
     * @param change derives the new key set from the stored one; it may run more than once.
     * @return the stored key set, or why it could not be changed, [KeysetFailure.Conflict] if other processes kept
     *   changing it for every attempt.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun update(name: String, change: suspend (Keyset) -> Keyset): Outcome<Keyset, KeysetFailure> {
        checkName(name)
        var result: Outcome<Keyset, KeysetFailure> = Outcome.Failure(KeysetFailure.Conflict)
        var attempt = 0
        while (attempt < attempts && result == Outcome.Failure(KeysetFailure.Conflict)) {
            result = attemptUpdate(name, change)
            attempt++
        }
        return result
    }

    /**
     * Deletes the key set stored under [name], which shreds by crypto everything it protected; the deletion is
     * recorded in the audit trail first.
     *
     * @param name the name.
     * @return true if a key set was deleted.
     * @throws IllegalArgumentException if [name] is invalid.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the deletion.
     * @since 1.0.0
     */
    public suspend fun delete(name: String): Boolean {
        checkName(name)
        trail.require(action = DELETE, subject = name)
        return repository.delete(name)
    }

    /**
     * Shows the service.
     *
     * @return the vault as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetVault($kms)"

    private suspend fun attemptUpdate(
        name: String,
        change: suspend (Keyset) -> Keyset,
    ): Outcome<Keyset, KeysetFailure> {
        val stored = repository.load(name) ?: return Outcome.Failure(KeysetFailure.Missing)
        val current = decrypt(name, stored)
        return when (current) {
            is Outcome.Failure -> current
            is Outcome.Success -> replace(name = name, stored = stored, changed = change(current.value))
        }
    }

    private suspend fun replace(name: String, stored: StoredKeyset, changed: Keyset): Outcome<Keyset, KeysetFailure> {
        val next = storedOf(name, changed, revision = stored.revision + 1)
        val isStored = repository.store(name = name, keyset = next, expectedRevision = stored.revision)
        return when (isStored) {
            true -> Outcome.Success(changed)
            false -> Outcome.Failure(KeysetFailure.Conflict)
        }
    }

    private suspend fun decrypt(name: String, stored: StoredKeyset): Outcome<Keyset, KeysetFailure> =
        keysets.decrypt(encrypted = stored.encrypted, kms = kms, associatedData = Bytes.utf8(name))

    private suspend fun storedOf(name: String, keyset: Keyset, revision: Long): StoredKeyset {
        val encrypted = keysets.encrypt(keyset = keyset, kms = kms, associatedData = Bytes.utf8(name))
        return StoredKeyset(revision = revision, encrypted = encrypted)
    }

    private fun checkName(name: String) {
        val isValid =
            name.length in 1..MAXIMUM_NAME_LENGTH && name.all { char -> char in FIRST_PRINTABLE..LAST_PRINTABLE }
        require(isValid) { "A key set name has 1 to $MAXIMUM_NAME_LENGTH printable ASCII characters" }
    }
}
