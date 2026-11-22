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

package com.davils.krypt.jose

import com.davils.krypt.jose.internal.HeaderNames
import com.davils.krypt.jose.internal.stringsOf
import com.davils.krypt.jose.internal.textOf

/**
 * The JOSE header of a signature or a recipient: the union of its protected and unprotected parts.
 *
 * The well-known members were checked for their types when the message was read, so the typed accessors never
 * fail. Their values come from the message and are not trusted before the signature or the decryption succeeded.
 *
 * @property members every member of the header.
 * @since 1.0.0
 */
public class JoseHeader(public val members: JsonValue.Object) {
    /**
     * The `alg` member.
     *
     * @since 1.0.0
     */
    public val algorithm: String? get() = members.textOf(HeaderNames.ALGORITHM)

    /**
     * The `enc` member of a JWE.
     *
     * @since 1.0.0
     */
    public val encryption: String? get() = members.textOf(HeaderNames.ENCRYPTION)

    /**
     * The `kid` member.
     *
     * @since 1.0.0
     */
    public val keyId: String? get() = members.textOf(HeaderNames.KEY_ID)

    /**
     * The `typ` member.
     *
     * @since 1.0.0
     */
    public val type: String? get() = members.textOf(HeaderNames.TYPE)

    /**
     * The `cty` member.
     *
     * @since 1.0.0
     */
    public val contentType: String? get() = members.textOf(HeaderNames.CONTENT_TYPE)

    /**
     * The `crit` member, empty if absent.
     *
     * @since 1.0.0
     */
    public val critical: List<String> get() = members.stringsOf(HeaderNames.CRITICAL).orEmpty()

    /**
     * Returns the member [name].
     *
     * @param name the member name.
     * @return the value, or null if absent.
     * @since 1.0.0
     */
    public operator fun get(name: String): JsonValue? = members[name]

    /**
     * Compares the members.
     *
     * @param other the other object.
     * @return true if [other] has the same members.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JoseHeader && members == other.members

    /**
     * Hashes the members.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = members.hashCode()

    /**
     * Shows the member names.
     *
     * @return the header as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JoseHeader($members)"
}
