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

package com.davils.krypt.asn1

import com.davils.krypt.asn1.internal.ReadContext
import kotlinx.io.bytestring.ByteString

/**
 * One element of a DER input: its tag, its content octets and its complete encoding.
 *
 * An element keeps the exact bytes it was read from, so a signed structure such as the to-be-signed part of a
 * certificate can be verified over the bytes that were signed, never over a re-encoding.
 *
 * @property tag the tag.
 * @property content the content octets.
 * @property encoded the complete encoding: identifier, length and content octets.
 * @since 1.0.0
 */
public class DerElement internal constructor(
    public val tag: Tag,
    public val content: ByteString,
    public val encoded: ByteString,
    private val depth: Int,
    private val context: ReadContext,
) {
    /**
     * Returns a reader over the elements inside a constructed element.
     *
     * @return the reader.
     * @throws DerException if the element is primitive, or nesting it breaks the depth limit.
     * @since 1.0.0
     */
    public fun reader(): DerReader {
        if (!tag.isConstructed) throw DerException(DerFailure.UnexpectedTag, "a constructed element, found $tag")
        context.checkDepth(depth + 1)
        val bytes = content.toByteArray()
        return DerReader(input = bytes, start = 0, end = bytes.size, depth = depth + 1, context = context)
    }

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is an element with the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DerElement && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the tag and the length, never the content, which may be secret.
     *
     * @return the element as text.
     * @since 1.0.0
     */
    override fun toString(): String = "DerElement($tag, length=${content.size})"
}
