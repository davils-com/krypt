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

package com.davils.krypt.cose.cbor

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.cose.internal.CborWriter
import com.davils.krypt.cose.internal.Utf8

/**
 * A text string of CBOR, of major type 3, encoded in UTF-8.
 *
 * @property text the text, which must not hold a lone surrogate, because UTF-8 cannot encode one.
 * @constructor Wraps [text].
 * @throws IllegalArgumentException if [text] holds a lone surrogate.
 * @since 1.0.0
 */
public class CborText(public val text: String) : CborItem() {
    init {
        require(Utf8.isWellFormed(text)) { "A text string of CBOR holds no lone surrogate" }
    }

    override fun write(writer: CborWriter) {
        val bytes = text.encodeToByteArray()
        writer.head(major = MAJOR, argument = bytes.size.toULong())
        writer.raw(bytes)
    }

    override fun textOrNull(): String = text

    /**
     * Compares the text.
     *
     * @param other the other object.
     * @return true if [other] is a text string with the same text.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborText && text == other.text

    /**
     * Hashes the text.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = text.hashCode()

    /**
     * Shows the text, quoted and escaped, because it may come from an attacker.
     *
     * @return the text as text.
     * @since 1.0.0
     */
    override fun toString(): String = "\"${SafeText.text(text)}\""

    private companion object {
        const val MAJOR: Int = 3
    }
}
