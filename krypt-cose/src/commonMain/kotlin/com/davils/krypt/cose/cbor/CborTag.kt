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

package com.davils.krypt.cose.cbor

import com.davils.krypt.cose.internal.CborWriter

/**
 * A tagged item of CBOR, of major type 6, such as a tagged COSE message.
 *
 * krypt keeps a tag as it is and checks only the tags that COSE and CWT define.
 *
 * @property number the tag number.
 * @property content the tagged item.
 * @constructor Tags [content] with [number].
 * @since 1.0.0
 */
public class CborTag(public val number: ULong, public val content: CborItem) : CborItem() {
    override fun write(writer: CborWriter) {
        writer.head(major = MAJOR, argument = number)
        content.write(writer)
    }

    override fun tagOrNull(): CborTag = this

    /**
     * Compares the number and the content.
     *
     * @param other the other object.
     * @return true if [other] is the same tag of an equal item.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborTag && number == other.number && content == other.content

    /**
     * Hashes the number and the content.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = number.hashCode() * HASH_FACTOR + content.hashCode()

    /**
     * Shows the tag in the diagnostic notation of CBOR, such as `18([...])`.
     *
     * @return the tag as text.
     * @since 1.0.0
     */
    override fun toString(): String = "$number($content)"

    private companion object {
        const val MAJOR: Int = 6
        const val HASH_FACTOR: Int = 31
    }
}
