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

package com.davils.krypt.ocsp

import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

/**
 * How a response names its responder.
 *
 * krypt does not use the identifier to find the signer: it tries the issuer and every certificate in the response.
 *
 * @since 1.0.0
 */
public sealed interface ResponderId {
    /**
     * By the DER encoding of the name of the responder.
     *
     * @property encoded the encoding of the name.
     * @constructor Names the responder.
     * @since 1.0.0
     */
    public class ByName(public val encoded: ByteString) : ResponderId {
        /**
         * Compares the encoding.
         *
         * @param other the other object.
         * @return true if [other] names the same responder.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is ByName && encoded == other.encoded

        /**
         * Hashes the encoding.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = encoded.hashCode()

        /**
         * Shows the encoding in hex.
         *
         * @return the identifier as text.
         * @since 1.0.0
         */
        override fun toString(): String = "ResponderId.ByName(${Hex.encode(encoded)})"
    }

    /**
     * By the SHA-1 digest of the public key of the responder.
     *
     * @property keyHash the digest.
     * @constructor Names the responder by its key.
     * @since 1.0.0
     */
    public class ByKey(public val keyHash: ByteString) : ResponderId {
        /**
         * Compares the digest.
         *
         * @param other the other object.
         * @return true if [other] names the same key.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is ByKey && keyHash == other.keyHash

        /**
         * Hashes the digest.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = keyHash.hashCode()

        /**
         * Shows the digest in hex.
         *
         * @return the identifier as text.
         * @since 1.0.0
         */
        override fun toString(): String = "ResponderId.ByKey(${Hex.encode(keyHash)})"
    }
}
