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

package com.davils.krypt.storage

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.KeysetAead
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.store.KeysetVault

private const val PREFIX: String = "subject/"

/**
 * One key set per subject, such as a person, a customer or a tenant, kept encrypted in a [vault], so that all data of
 * one subject is shredded by deleting its key set: the right to erasure without finding every copy of the data.
 *
 * Encrypt the data of a subject with [aead], directly, with a [com.davils.krypt.storage.record.RecordCipher] or as
 * the data keys of an [com.davils.krypt.storage.blob.EncryptedBlobStore]; [shred] then makes all of it unreadable,
 * also in backups, as long as the vault keeps no copy of the deleted key set. Give the vault a
 * [com.davils.krypt.keyset.store.RevisionLedger] for that: without one, the vault trusts its repository to delete for
 * good, and a key set that a repository or a restored backup serves again brings the data back.
 *
 * @property vault where the key sets of the subjects are kept.
 * @constructor Keeps subject keys in [vault].
 * @since 1.0.0
 */
public class SubjectKeys(public val vault: KeysetVault) {
    /**
     * Returns the encryption of [subject], creating its key set on first use.
     *
     * @param subject the subject: 1 to 200 printable ASCII characters.
     * @return the encryption, or why the key set of [subject] could not be read.
     * @throws IllegalArgumentException if [subject] is invalid.
     * @since 1.0.0
     */
    public suspend fun aead(subject: String): Outcome<KeysetAead, KeysetFailure> {
        val name = nameOf(subject)
        val loaded = vault.load(name)
        val keyset = when (loaded) {
            is Outcome.Success -> loaded
            is Outcome.Failure -> createdOr(name, loaded)
        }
        return when (keyset) {
            is Outcome.Success -> Outcome.Success(vault.keysets.aead(keyset.value))
            is Outcome.Failure -> keyset
        }
    }

    /**
     * Rotates the key set of [subject]; data encrypted before stays readable.
     *
     * @param subject the subject.
     * @return the rotated key set, or why it could not be rotated.
     * @throws IllegalArgumentException if [subject] is invalid.
     * @since 1.0.0
     */
    public suspend fun rotate(subject: String): Outcome<Keyset, KeysetFailure> =
        vault.update(nameOf(subject)) { keyset -> vault.keysets.rotate(keyset) }

    /**
     * Deletes the key set of [subject], which makes all data encrypted for it unreadable.
     *
     * @param subject the subject.
     * @return true if a key set was deleted.
     * @throws IllegalArgumentException if [subject] is invalid.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if a required audit could not record the deletion.
     * @since 1.0.0
     */
    public suspend fun shred(subject: String): Boolean = vault.delete(nameOf(subject))

    /**
     * Shows the vault.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SubjectKeys($vault)"

    private suspend fun createdOr(
        name: String,
        failure: Outcome.Failure<KeysetFailure>,
    ): Outcome<Keyset, KeysetFailure> {
        val isMissing = failure.failure == KeysetFailure.Missing
        val created = vault.create(name, KeyPurpose.Aead()).takeIf { isMissing } ?: return failure
        val isRace = created == Outcome.Failure(KeysetFailure.Conflict)
        return vault.load(name).takeIf { isRace } ?: created
    }

    private fun nameOf(subject: String): String {
        require(subject.length in 1..MAXIMUM_SUBJECT) { "A subject has 1 to $MAXIMUM_SUBJECT characters" }
        return PREFIX + subject
    }

    private companion object {
        const val MAXIMUM_SUBJECT: Int = 200
    }
}
