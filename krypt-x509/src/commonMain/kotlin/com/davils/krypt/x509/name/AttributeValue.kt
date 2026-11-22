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

package com.davils.krypt.x509.name

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.x509.internal.AttributeParts
import kotlinx.io.bytestring.ByteString

/**
 * One attribute of a distinguished name, such as `CN=example.com`.
 *
 * @property type the attribute type.
 * @property text the value as text, or null if it is not a string.
 * @property tag the tag of the value, such as UTF8String or PrintableString.
 * @property encoded the DER encoding of the value.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class AttributeValue private constructor(
    public val type: ObjectIdentifier,
    public val text: String?,
    public val tag: Tag,
    public val encoded: ByteString,
) {
    private val normalizedText: String? = text?.let { value -> normalize(value) }

    internal val normalized: String = normalizedText ?: "#${Hex.encode(encoded)}"

    internal constructor(parts: AttributeParts) : this(
        type = parts.type,
        text = parts.text,
        tag = parts.tag,
        encoded = parts.encoded,
    )

    /**
     * Compares by RFC 5280: the type, and the value of a string ignoring case and surplus white space, otherwise its
     * encoding.
     *
     * @param other the other object.
     * @return true if [other] is the same attribute.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is AttributeValue && type == other.type && normalized == other.normalized

    /**
     * Hashes the type and the normalised value.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(type, normalized).hashCode()

    /**
     * Shows the attribute by RFC 4514, escaped for safe display.
     *
     * @return the attribute as text.
     * @since 1.0.0
     */
    override fun toString(): String = SafeText.text(rfc4514())

    internal fun rfc4514(): String {
        val name = AttributeTypes.SHORT_NAMES[type] ?: type.dotted
        val escaped = text?.let { found -> escape(found) }
        val value = escaped ?: "#${Hex.encode(encoded)}"
        return "$name=$value"
    }

    private companion object {
        val SPECIAL: Set<Char> = setOf(',', '+', '"', '\\', '<', '>', ';', '=')
        const val LAST_CONTROL: Char = '\u001f'

        fun normalize(value: String): String {
            val trimmed = value.trim()
            val words = trimmed.split(' ', '\t', '\n', '\r').filter { word -> word.isNotEmpty() }
            return words.joinToString(" ").lowercase()
        }

        fun escape(value: String): String = buildString {
            value.forEachIndexed { index, char ->
                val isEdge = (index == 0 && (char == ' ' || char == '#')) || (index == value.length - 1 && char == ' ')
                val isControl = char <= LAST_CONTROL
                if (char in SPECIAL || isEdge) append('\\')
                val shown = listOf(char.toString(), "\\${Hex.encode(byteArrayOf(char.code.toByte()))}")
                append(shown[isControl.compareTo(false)])
            }
        }
    }
}
