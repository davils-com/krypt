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
import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.telemetry.AuditTrail
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.keyset.internal.Refusal
import com.davils.krypt.keyset.internal.Refusal.Companion.ensure
import com.davils.krypt.keyset.internal.Refusal.Companion.refuse
import com.davils.krypt.keyset.kms.KeyManagementService
import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_NAME_LENGTH: Int = 256
private const val DEFAULT_ATTEMPTS: Int = 3
private const val MAXIMUM_ATTEMPTS: Int = 16
private const val FIRST_PRINTABLE: Char = ' '
private const val LAST_PRINTABLE: Char = '~'
private const val LABEL: String = "krypt keyset vault v1 "
private const val REVISION_BYTES: Int = 8
private const val BYTE_BITS: Int = 8
private val DELETE: AuditAction = AuditAction("keyset.delete")

/**
 * Keeps named key sets in a [repository], encrypted by [kms] and bound to their names and revisions, and changes them
 * safely under concurrency.
 *
 * Every key set is encrypted with its name and its revision as associated data, so a key set copied under another
 * name, or under another revision of the same name, is refused as [KeysetFailure.DecryptionFailed]. [update] reads,
 * changes and stores with the revision of the repository and tries again when another process changed the key set in
 * between.
 *
 * **Rollback.** Without a [ledger], the vault trusts the repository to serve the latest revision: a repository, a
 * restored backup or an attacker that controls the storage can serve an older revision whole, and the vault accepts
 * it, so a key that [Keysets.destroy] wiped, a key that was rotated away after a compromise, or a key set that
 * [delete] removed comes back. [delete], and shredding by crypto on top of it, then rely on the repository alone.
 * With a [ledger], the vault refuses as [KeysetFailure.Rollback] every key set whose revision is lower than the one
 * the ledger records. The ledger is advanced after the repository stored a key set, so a failure in between leaves
 * it behind and never locks a key set out; the next [load] or [update] that decrypts the newer revision advances it.
 * [delete] records a revision past the deleted one before the repository deletes it, so a deleted key set that
 * reappears is refused, and a key set created again under the name starts after it. A name the ledger has never seen
 * is accepted and recorded.
 *
 * **Failures.** The repository, the ledger and [kms] are the code of the application: what they throw in [create],
 * [load] and [update] is contained and becomes [KeysetFailure.Unavailable], without its message, and a ledger that
 * fails after the repository stored a key set only leaves the ledger behind; a cancellation of the caller passes on.
 *
 * The vault holds no key of its own and is safe to share between threads; the repository and the ledger order
 * concurrent changes.
 *
 * @property keysets the key sets and their primitives.
 * @param repository where the encrypted key sets are kept.
 * @param kms the service that encrypts them.
 * @property attempts how often [update] tries when another process changes the same key set; 1 to 16, 3 by default.
 * @param ledger the trusted record of the latest revisions, or null.
 * @constructor Keeps key sets in [repository].
 * @throws IllegalArgumentException if [attempts] is out of range.
 * @since 1.0.0
 */
public class KeysetVault(
    public val keysets: Keysets,
    private val repository: KeysetRepository,
    private val kms: KeyManagementService,
    public val attempts: Int = DEFAULT_ATTEMPTS,
    private val ledger: RevisionLedger? = null,
) {
    private val trail = AuditTrail(keysets.crypto.environment)

    init {
        require(attempts in 1..MAXIMUM_ATTEMPTS) { "A vault tries 1 to $MAXIMUM_ATTEMPTS times" }
    }

    /**
     * Generates a key set of [purpose] and stores it under [name].
     *
     * The key set is generated, and its generation audited, before it is stored, so a conflict leaves an audited key
     * that was never stored.
     *
     * @param name the name: 1 to 256 printable ASCII characters.
     * @param purpose what the keys are for.
     * @return the key set, or [KeysetFailure.Conflict] if a key set is stored under [name] already, or
     *   [KeysetFailure.Unavailable] if the repository, the ledger or the key management service failed.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun create(name: String, purpose: KeyPurpose): Outcome<Keyset, KeysetFailure> {
        checkName(name)
        val keyset = keysets.generate(purpose)
        return guarded {
            val revision = (recorded(name) ?: 0L) + 1
            val stored = storedOf(name = name, keyset = keyset, revision = revision)
            val isStored = foreign { repository.store(name = name, keyset = stored, expectedRevision = null) }
            ensure(isStored, KeysetFailure.Conflict)
            guarded { advance(name, revision) }
            keyset
        }
    }

    /**
     * Loads and decrypts the key set stored under [name].
     *
     * @param name the name.
     * @return the key set, or why it could not be read, [KeysetFailure.Missing] if none is stored under [name],
     *   [KeysetFailure.Rollback] if it is older than the ledger records.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun load(name: String): Outcome<Keyset, KeysetFailure> {
        checkName(name)
        return guarded { opened(name, loaded(name)) }
    }

    /**
     * Changes the key set stored under [name] with [change], such as `keysets::rotate`, and stores the result.
     *
     * @param name the name.
     * @param change derives the new key set from the stored one; it may run more than once, and what it audits is
     *   audited once per run.
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
            result = guarded { changed(name, change) }
            attempt++
        }
        return result
    }

    /**
     * Deletes the key set stored under [name], which shreds by crypto everything it protected; the deletion is
     * recorded in the audit trail first and, with a ledger, in the ledger before the repository deletes the key set.
     *
     * @param name the name.
     * @return true if a key set was deleted.
     * @throws IllegalArgumentException if [name] is invalid.
     * @throws IllegalStateException if the ledger failed or other processes kept changing it; nothing is deleted then.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the deletion.
     * @since 1.0.0
     */
    public suspend fun delete(name: String): Boolean {
        checkName(name)
        trail.require(action = DELETE, subject = name)
        val recorded = guarded { ledger == null || deletionRecorded(name) }
        check(recorded == Outcome.Success(true)) { "The ledger did not record the deletion" }
        return repository.delete(name)
    }

    /**
     * Shows the service.
     *
     * @return the vault as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetVault($kms)"

    private suspend fun changed(name: String, change: suspend (Keyset) -> Keyset): Keyset {
        val stored = loaded(name)
        val changed = change(opened(name, stored))
        val revision = stored.revision + 1
        val next = storedOf(name = name, keyset = changed, revision = revision)
        val isStored = foreign { repository.store(name = name, keyset = next, expectedRevision = stored.revision) }
        ensure(isStored, KeysetFailure.Conflict)
        guarded { advance(name, revision) }
        return changed
    }

    private suspend fun deletionRecorded(name: String): Boolean {
        val stored = foreign { repository.load(name) }
        val highest = maxOf(a = stored?.revision ?: 0L, b = recorded(name) ?: 0L)
        return advance(name, minOf(a = highest, b = Long.MAX_VALUE - 1) + 1)
    }

    private suspend fun loaded(name: String): StoredKeyset =
        foreign { repository.load(name) } ?: refuse(KeysetFailure.Missing)

    private suspend fun opened(name: String, stored: StoredKeyset): Keyset {
        val recorded = recorded(name) ?: 0L
        ensure(stored.revision >= recorded, KeysetFailure.Rollback)
        val decrypted = keysets.decrypt(
            encrypted = stored.encrypted,
            kms = kms,
            associatedData = contextOf(name, stored.revision),
        )
        val keyset = when (decrypted) {
            is Outcome.Success -> decrypted.value
            is Outcome.Failure -> refuse(decrypted.failure)
        }
        advance(name, stored.revision)
        return keyset
    }

    private suspend fun recorded(name: String): Long? = ledger?.let { found -> foreign { found.current(name) } }

    private suspend fun advance(name: String, revision: Long): Boolean {
        val found = ledger ?: return true
        var attempt = 0
        var isAdvanced = false
        while (attempt < attempts && !isAdvanced) {
            val current = foreign { found.current(name) }
            val isAhead = current != null && current >= revision
            isAdvanced = isAhead || foreign { found.record(name = name, revision = revision, expected = current) }
            attempt++
        }
        return isAdvanced
    }

    private suspend fun storedOf(name: String, keyset: Keyset, revision: Long): StoredKeyset {
        val context = contextOf(name, revision)
        val encrypted = foreign { keysets.encrypt(keyset = keyset, kms = kms, associatedData = context) }
        return StoredKeyset(revision = revision, encrypted = encrypted)
    }

    private fun contextOf(name: String, revision: Long): ByteString {
        val bytes = ByteArray(REVISION_BYTES) { index ->
            (revision ushr (REVISION_BYTES - 1 - index) * BYTE_BITS).toByte()
        }
        return Bytes.concat(Bytes.utf8(LABEL), ByteString(bytes), Bytes.utf8(name))
    }

    private suspend inline fun <T> foreign(block: () -> T): T {
        val result = attempted(block)
        return result.getOrElse { _ -> refuse(KeysetFailure.Unavailable) }
    }

    private suspend fun <T> guarded(block: suspend () -> T): Outcome<T, KeysetFailure> = try {
        Outcome.Success(block())
    } catch (refusal: Refusal) {
        Outcome.Failure(refusal.failure)
    }

    private fun checkName(name: String) {
        val isValid =
            name.length in 1..MAXIMUM_NAME_LENGTH && name.all { char -> char in FIRST_PRINTABLE..LAST_PRINTABLE }
        require(isValid) { "A key set name has 1 to $MAXIMUM_NAME_LENGTH printable ASCII characters" }
    }
}
