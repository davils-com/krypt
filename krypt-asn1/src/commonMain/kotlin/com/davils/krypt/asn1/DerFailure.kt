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

/**
 * Why bytes are not the DER encoding krypt expected.
 *
 * DER allows exactly one encoding of every value; krypt refuses every other encoding, because two encodings of one
 * certificate or signature would let an attacker change signed bytes without changing their meaning.
 *
 * @since 1.0.0
 */
public enum class DerFailure {
    /**
     * An element runs past the end of its enclosing element or of the input.
     *
     * @since 1.0.0
     */
    Truncated,

    /**
     * A length or a tag number is not in its shortest form, or a length uses the indefinite form of BER.
     *
     * @since 1.0.0
     */
    NonMinimalEncoding,

    /**
     * A value has a form DER forbids, such as an INTEGER with a redundant leading byte, a BOOLEAN other than 0x00 or
     * 0xFF, a BIT STRING with set unused bits or a time with a fraction ending in zero.
     *
     * @since 1.0.0
     */
    NonCanonicalValue,

    /**
     * An element has another tag than the structure expects.
     *
     * @since 1.0.0
     */
    UnexpectedTag,

    /**
     * A value is malformed, such as a string with a character its type forbids, an impossible date or an object
     * identifier with an invalid arc.
     *
     * @since 1.0.0
     */
    InvalidValue,

    /**
     * Bytes follow where the structure ends.
     *
     * @since 1.0.0
     */
    TrailingData,

    /**
     * The input breaks a limit of [DerLimits], such as its size, its depth or its number of elements.
     *
     * @since 1.0.0
     */
    LimitExceeded,
}
