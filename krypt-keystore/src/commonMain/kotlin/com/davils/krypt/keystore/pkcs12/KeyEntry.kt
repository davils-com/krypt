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

package com.davils.krypt.keystore.pkcs12

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.keystore.Identity

/**
 * A private key with the chain of its certificate in a PKCS #12 file.
 *
 * @property identity the key and its chain.
 * @property alias the friendly name, or null.
 * @constructor Creates the entry.
 * @since 1.0.0
 */
public class KeyEntry(public val identity: Identity, public val alias: String? = null) {
    /**
     * Compares the alias and the identity.
     *
     * @param other the other object.
     * @return true if [other] is the same entry.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is KeyEntry && alias == other.alias && identity == other.identity

    /**
     * Hashes the alias and the identity.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(alias, identity).hashCode()

    /**
     * Shows the alias and the identity, never the key.
     *
     * @return the entry as text.
     * @since 1.0.0
     */
    @OptIn(DavilsInternal::class)
    override fun toString(): String {
        val shown = SafeText.text(alias ?: "none")
        return "KeyEntry($shown, $identity)"
    }
}
