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

package com.davils.krypt.core.encoding

/**
 * Why a text is not a valid encoding. The failure names no position, because the decoded bytes may be secret.
 *
 * @since 1.0.0
 */
public enum class EncodingFailure {
    /**
     * A character lies outside the alphabet of the encoding.
     *
     * @since 1.0.0
     */
    InvalidCharacter,

    /**
     * The length cannot be the length of an encoding, such as an odd number of hexadecimal digits.
     *
     * @since 1.0.0
     */
    InvalidLength,

    /**
     * The padding is missing where it is required, present where it is forbidden, or in the wrong place.
     *
     * @since 1.0.0
     */
    InvalidPadding,

    /**
     * The text decodes, but is not the one canonical encoding of its bytes, such as Base64 whose unused bits are not
     * zero. Two texts for the same bytes would let an attacker change a signed text without changing its meaning.
     *
     * @since 1.0.0
     */
    NonCanonical,

    /**
     * The text is longer than the limit of the decoder.
     *
     * @since 1.0.0
     */
    TooLong,
}
