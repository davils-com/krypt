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

package com.davils.krypt.keystore.material

import kotlinx.io.bytestring.ByteString

/**
 * What a [MaterialSource] found.
 *
 * @since 1.0.0
 */
public sealed interface MaterialRead {
    /**
     * The material.
     *
     * @property bytes the bytes.
     * @constructor Wraps [bytes].
     * @since 1.0.0
     */
    public class Found(public val bytes: ByteString) : MaterialRead {
        /**
         * Compares the bytes.
         *
         * @param other the other object.
         * @return true if [other] found the same bytes.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Found && bytes == other.bytes

        /**
         * Hashes the size only, since the bytes may be secret.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = bytes.size

        /**
         * Shows the size only, since the bytes may be secret.
         *
         * @return the result as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Found(size=${bytes.size})"
    }

    /**
     * Nothing exists under the reference.
     *
     * @since 1.0.0
     */
    public data object Missing : MaterialRead

    /**
     * The source could not be read now, such as a secret store that does not answer; trying again may help.
     *
     * @since 1.0.0
     */
    public data object Unavailable : MaterialRead
}
