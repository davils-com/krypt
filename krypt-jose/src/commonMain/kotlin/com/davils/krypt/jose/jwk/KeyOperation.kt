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

package com.davils.krypt.jose.jwk

/**
 * The operations a key is meant for, the `key_ops` member of a JWK.
 *
 * @property operationName the name in a JWK.
 * @property use the use the operation belongs to, which a JWK with both `use` and `key_ops` must agree with.
 * @since 1.0.0
 */
public enum class KeyOperation(public val operationName: String, public val use: KeyUse) {
    /**
     * Computing a signature or a MAC.
     *
     * @since 1.0.0
     */
    Sign("sign", KeyUse.Signature),

    /**
     * Verifying a signature or a MAC.
     *
     * @since 1.0.0
     */
    Verify("verify", KeyUse.Signature),

    /**
     * Encrypting content.
     *
     * @since 1.0.0
     */
    Encrypt("encrypt", KeyUse.Encryption),

    /**
     * Decrypting content and validating its decryption.
     *
     * @since 1.0.0
     */
    Decrypt("decrypt", KeyUse.Encryption),

    /**
     * Encrypting a key.
     *
     * @since 1.0.0
     */
    WrapKey("wrapKey", KeyUse.Encryption),

    /**
     * Decrypting a key and validating its decryption.
     *
     * @since 1.0.0
     */
    UnwrapKey("unwrapKey", KeyUse.Encryption),

    /**
     * Deriving a key.
     *
     * @since 1.0.0
     */
    DeriveKey("deriveKey", KeyUse.Encryption),

    /**
     * Deriving bits that are not used as a key.
     *
     * @since 1.0.0
     */
    DeriveBits("deriveBits", KeyUse.Encryption),
    ;

    /**
     * The lookup by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the operation named [name].
         *
         * @param name the name in a JWK.
         * @return the operation, or null if krypt does not know it.
         * @since 1.0.0
         */
        public fun of(name: String): KeyOperation? =
            entries.firstOrNull { operation -> operation.operationName == name }
    }
}
