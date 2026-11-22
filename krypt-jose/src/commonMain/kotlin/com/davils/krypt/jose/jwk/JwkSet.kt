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

package com.davils.krypt.jose.jwk

import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.JwkWriter

/**
 * A JWK set of RFC 7517: the keys of an issuer, as a JWKS endpoint publishes them.
 *
 * @param keys the keys, copied.
 * @since 1.0.0
 */
public class JwkSet(keys: List<Jwk>) {
    /**
     * The keys in order.
     *
     * @since 1.0.0
     */
    public val keys: List<Jwk> = keys.toList()

    /**
     * Returns the keys with the key id [keyId].
     *
     * @param keyId the key id.
     * @return the matching keys, empty if none matches.
     * @since 1.0.0
     */
    public fun find(keyId: String): List<Jwk> = keys.filter { key -> key.keyId == keyId }

    /**
     * Returns the set without private parameters; symmetric keys are left out.
     *
     * @return the public set, as a JWKS endpoint publishes it.
     * @since 1.0.0
     */
    public fun toPublic(): JwkSet = JwkSet(keys.mapNotNull { key -> key.toPublic() })

    /**
     * Writes the set as compact JSON, private parameters included.
     *
     * @return the JSON text.
     * @throws IllegalStateException if a key was destroyed.
     * @since 1.0.0
     */
    public fun encode(): String {
        check(keys.none { key -> key.isDestroyed }) { "A key of the set was destroyed" }
        val array = JsonValue.Array(keys.map { key -> JwkWriter.objectOf(key) })
        return JsonValue.Object.of(KEYS to array).encode()
    }

    /**
     * Compares the keys in order.
     *
     * @param other the other object.
     * @return true if [other] holds equal keys in the same order.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwkSet && keys == other.keys

    /**
     * Hashes the keys.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = keys.hashCode()

    /**
     * Shows the keys.
     *
     * @return the set as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JwkSet($keys)"

    private companion object {
        const val KEYS: String = "keys"
    }
}
