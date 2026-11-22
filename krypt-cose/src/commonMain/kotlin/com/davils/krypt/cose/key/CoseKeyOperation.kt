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

package com.davils.krypt.cose.key

/**
 * An operation a COSE_Key permits, an entry of its `key_ops`.
 *
 * A key without operations permits every operation its type allows; a key with operations permits only those.
 *
 * @property id the value of the operation in the COSE registry.
 * @since 1.0.0
 */
public enum class CoseKeyOperation(public val id: Long) {
    /**
     * Creating a signature.
     *
     * @since 1.0.0
     */
    Sign(id = 1),

    /**
     * Verifying a signature.
     *
     * @since 1.0.0
     */
    Verify(id = 2),

    /**
     * Encrypting content.
     *
     * @since 1.0.0
     */
    Encrypt(id = 3),

    /**
     * Decrypting content.
     *
     * @since 1.0.0
     */
    Decrypt(id = 4),

    /**
     * Wrapping a key.
     *
     * @since 1.0.0
     */
    WrapKey(id = 5),

    /**
     * Unwrapping a key.
     *
     * @since 1.0.0
     */
    UnwrapKey(id = 6),

    /**
     * Deriving a key.
     *
     * @since 1.0.0
     */
    DeriveKey(id = 7),

    /**
     * Deriving bits that are not a key.
     *
     * @since 1.0.0
     */
    DeriveBits(id = 8),

    /**
     * Creating a MAC.
     *
     * @since 1.0.0
     */
    MacCreate(id = 9),

    /**
     * Verifying a MAC.
     *
     * @since 1.0.0
     */
    MacVerify(id = 10),
}
