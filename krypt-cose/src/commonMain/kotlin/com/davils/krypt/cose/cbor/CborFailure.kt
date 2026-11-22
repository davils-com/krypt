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

/**
 * Why an encoding of CBOR was refused.
 *
 * @since 1.0.0
 */
public enum class CborFailure {
    /**
     * The input ends inside a data item.
     *
     * @since 1.0.0
     */
    Truncated,

    /**
     * The input is not well formed by RFC 8949: a reserved additional information, a break outside an
     * indefinite-length item, or a simple value below 32 in two bytes.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * A text string is not valid UTF-8: an overlong form, a surrogate, a code point above U+10FFFF or a broken
     * sequence.
     *
     * @since 1.0.0
     */
    InvalidText,

    /**
     * The input is well formed but not deterministic by RFC 8949 section 4.2.1: an argument or a float that is not as
     * short as it could be, or map keys out of order.
     *
     * @since 1.0.0
     */
    NotDeterministic,

    /**
     * An indefinite-length string, array or map, which krypt never reads.
     *
     * @since 1.0.0
     */
    IndefiniteLength,

    /**
     * A map holds the same key twice.
     *
     * @since 1.0.0
     */
    DuplicateKey,

    /**
     * The input breaks one of the [CborLimits].
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * Bytes follow the data item.
     *
     * @since 1.0.0
     */
    TrailingData,
}
