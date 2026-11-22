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

import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlin.time.Instant

/**
 * One key of a [Keyset]: its id, its status, when it was created and its material.
 *
 * A symmetric key holds a [secret]; an asymmetric key holds a [privateKey] and its [publicKey], or only the public key
 * in a public key set. A destroyed key holds no material at all.
 *
 * @property id the id of the key.
 * @property status the state of the key.
 * @property createdAt when the key was created.
 * @property secret the symmetric key, or null.
 * @property privateKey the private key, or null.
 * @property publicKey the public key, or null.
 * @since 1.0.0
 */
public class KeysetKey internal constructor(
    public val id: KeyId,
    public val status: KeyStatus,
    public val createdAt: Instant,
    public val secret: SecretKey?,
    public val privateKey: PrivateKey?,
    public val publicKey: PublicKey?,
) {
    /**
     * Whether the key may be used: it is enabled, so its material is there.
     *
     * @since 1.0.0
     */
    public val isUsable: Boolean get() = status == KeyStatus.Enabled

    internal fun withStatus(changed: KeyStatus): KeysetKey = KeysetKey(
        id = id,
        status = changed,
        createdAt = createdAt,
        secret = secret,
        privateKey = privateKey,
        publicKey = publicKey,
    )

    internal fun destroyed(): KeysetKey = KeysetKey(
        id = id,
        status = KeyStatus.Destroyed,
        createdAt = createdAt,
        secret = null,
        privateKey = null,
        publicKey = null,
    )

    internal fun publicOnly(): KeysetKey = KeysetKey(
        id = id,
        status = status,
        createdAt = createdAt,
        secret = null,
        privateKey = null,
        publicKey = publicKey,
    )

    /**
     * Compares the id, the status, the time of creation and the material: a secret in constant time, a key pair by its
     * public key, which the private key was proven to belong to.
     *
     * @param other the other object.
     * @return true if [other] is the same key.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is KeysetKey &&
        id == other.id &&
        status == other.status &&
        createdAt == other.createdAt &&
        secret == other.secret &&
        publicKey == other.publicKey

    /**
     * Hashes the id.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = id.hashCode()

    /**
     * Shows the id, the status and the time of creation, never the material.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetKey($id, $status, createdAt=$createdAt)"
}
