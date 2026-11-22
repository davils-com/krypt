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

package com.davils.krypt.keyset

import com.davils.krypt.keyset.internal.KeyTypes

/**
 * A set of keys of one [purpose] with one primary key: the primary key protects new data, and every enabled key opens
 * and verifies what it protected, so keys can be rotated without re-encrypting everything at once.
 *
 * A key set is immutable: [Keysets] returns a new key set for every change. Keys are shared between the versions of a
 * key set, so destroying a key wipes its material in every version that holds it. A key set is safe to share between
 * threads; it never shows its material in [toString]. However it was built, a key set holds every key id once, an
 * enabled primary key and only material that fits its purpose, and its primitives match that purpose.
 *
 * @property purpose what the keys are for.
 * @property primaryId the id of the primary key.
 * @since 1.0.0
 */
public class Keyset internal constructor(
    public val purpose: KeyPurpose,
    keys: List<KeysetKey>,
    public val primaryId: KeyId,
) {
    /**
     * Every key, oldest first.
     *
     * @since 1.0.0
     */
    public val keys: List<KeysetKey> = keys.toList()

    /**
     * The primary key.
     *
     * @since 1.0.0
     */
    public val primary: KeysetKey = requireNotNull(this.keys.firstOrNull { key -> key.id == primaryId }) {
        "A key set holds its primary key"
    }

    /**
     * Whether the key set holds public keys only, so it can verify and encrypt but not sign or decrypt.
     *
     * @since 1.0.0
     */
    public val isPublic: Boolean get() = keys.all { key -> key.secret == null && key.privateKey == null }

    init {
        val ids = keys.map { key -> key.id }
        require(ids.toSet().size == ids.size) { "A key set holds every id once" }
        require(primary.status == KeyStatus.Enabled) { "The primary key is enabled" }
        require(this.keys.all { key -> fits(key) }) { "Every key of a key set has the material its purpose needs" }
    }

    /**
     * Returns the key with [id].
     *
     * @param id the id.
     * @return the key, or null if the key set has none with [id].
     * @since 1.0.0
     */
    public operator fun get(id: KeyId): KeysetKey? = keys.firstOrNull { key -> key.id == id }

    internal fun <M : Any> usable(material: (KeysetKey) -> M?): List<Pair<KeyId, M>> {
        val enabled = keys.filter { key -> key.isUsable }
        return enabled.mapNotNull { key -> material(key)?.let { found -> key.id to found } }
    }

    internal fun replaced(key: KeysetKey): Keyset {
        val replaced = keys.map { existing -> existing.takeUnless { found -> found.id == key.id } ?: key }
        return Keyset(purpose = purpose, keys = replaced, primaryId = primaryId)
    }

    private fun fits(key: KeysetKey): Boolean {
        val type = purpose.keyType
        val secret = key.secret
        val public = key.publicKey
        val isSized = secret == null || secret.bits == purpose.secretBytes * Byte.SIZE_BITS
        val isSymmetric = type == null && public == null && isSized
        val isAsymmetric = type != null && secret == null && (public == null || KeyTypes.matches(type, public))
        return isSymmetric || isAsymmetric
    }

    internal fun keyOf(id: KeyId): KeysetKey = requireNotNull(get(id)) { "The key set has no key $id" }

    /**
     * Compares the purpose, the primary key and every key.
     *
     * @param other the other object.
     * @return true if [other] is the same key set.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Keyset &&
        purpose == other.purpose &&
        primaryId == other.primaryId &&
        keys == other.keys

    /**
     * Hashes the purpose and the primary key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(purpose, primaryId).hashCode()

    /**
     * Shows the purpose, the primary key and the number of keys, never the material.
     *
     * @return the key set as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Keyset($purpose, primary=$primaryId, keys=${keys.size})"
}
