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

package com.davils.krypt.cose

/**
 * A message type of RFC 9052 with its CBOR tag.
 *
 * @property tag the CBOR tag of the type.
 * @since 1.0.0
 */
public enum class CoseMessageType(public val tag: ULong) {
    /**
     * COSE_Sign1, a message with one signature.
     *
     * @since 1.0.0
     */
    Sign1(tag = 18UL),

    /**
     * COSE_Sign, a message with one or more signatures.
     *
     * @since 1.0.0
     */
    Sign(tag = 98UL),

    /**
     * COSE_Mac0, a message with a MAC whose key the recipient knows.
     *
     * @since 1.0.0
     */
    Mac0(tag = 17UL),

    /**
     * COSE_Mac, a message with a MAC and recipients of its key.
     *
     * @since 1.0.0
     */
    Mac(tag = 97UL),

    /**
     * COSE_Encrypt0, encrypted content whose key the recipient knows.
     *
     * @since 1.0.0
     */
    Encrypt0(tag = 16UL),

    /**
     * COSE_Encrypt, encrypted content with recipients of its key.
     *
     * @since 1.0.0
     */
    Encrypt(tag = 96UL),
}
