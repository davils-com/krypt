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
import com.davils.krypt.cose.internal.Floats

/**
 * A floating-point number of CBOR, of major type 7, such as a NumericDate of a CWT with a fraction.
 *
 * The writer chooses the shortest of half, single and double precision that keeps the value exactly, as the preferred
 * serialization of RFC 8949 section 4.2.1 demands, and writes every NaN as the half-precision `0xf97e00`.
 *
 * @property value the number.
 * @constructor Wraps [value].
 * @since 1.0.0
 */
public class CborFloat(public val value: Double) : CborItem() {
    override fun write(writer: CborWriter) {
        writer.raw(Floats.encode(value))
    }

    override fun floatOrNull(): CborFloat = this

    /**
     * Compares the bits of the number, so that NaN equals NaN with the same payload and 0.0 differs from -0.0.
     *
     * @param other the other object.
     * @return true if [other] is a number with the same bits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CborFloat && value.toRawBits() == other.value.toRawBits()

    /**
     * Hashes the bits of the number.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = value.toRawBits().hashCode()

    /**
     * Shows the number.
     *
     * @return the number as text.
     * @since 1.0.0
     */
    override fun toString(): String = value.toString()
}
