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

import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.cose.internal.CborWriter
import kotlinx.io.bytestring.ByteString

/**
 * A byte string of CBOR, of major type 2.
 *
 * The text form shows the bytes in hex; a byte string that holds a secret, such as the key of a COSE_Key, must not
 * be shown.
 *
 * @property bytes the bytes.
 * @constructor Wraps [bytes].
 * @since 1.0.0
 */
public class CborBytes(public val bytes: ByteString) : CborItem() {
    override fun write(writer: CborWriter) {
        writer.head(major = MAJOR, argument = bytes.size.toULong())
        writer.raw(bytes)
    }

    override fun bytesOrNull(): ByteString = bytes

    /**
     * Compares the bytes.
     *
     * @param other the other object.
     * @return true if [other] is a byte string with the same bytes.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborBytes && bytes == other.bytes

    /**
     * Hashes the bytes.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = bytes.hashCode()

    /**
     * Shows the bytes in the diagnostic notation of CBOR, such as `h'0102'`.
     *
     * @return the bytes as text.
     * @since 1.0.0
     */
    override fun toString(): String = "h'${Hex.encode(bytes)}'"

    private companion object {
        const val MAJOR: Int = 2
    }
}
