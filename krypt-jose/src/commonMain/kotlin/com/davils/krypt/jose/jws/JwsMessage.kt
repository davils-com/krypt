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

package com.davils.krypt.jose.jws

import kotlinx.io.bytestring.ByteString

/**
 * A decoded JWS whose signatures are not verified yet. Nothing in it may be trusted before [Jws.verify] succeeded;
 * the headers only help to choose the keys.
 *
 * @property signatures the signatures, one in the compact and the flattened serialization.
 * @property payload the payload, or null if it is detached.
 * @property isCompact whether the message came in the compact serialization.
 * @property isPayloadEncoded false if the payload is unencoded by RFC 7797 (`b64` false).
 * @property payloadPart the payload as it came in the serialization.
 * @since 1.0.0
 */
public class JwsMessage internal constructor(
    public val signatures: List<JwsSignature>,
    public val payload: ByteString?,
    public val isCompact: Boolean,
    public val isPayloadEncoded: Boolean,
    internal val payloadPart: String,
) {
    /**
     * Compares the signatures and the payload.
     *
     * @param other the other object.
     * @return true if [other] is the same message.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwsMessage &&
        signatures == other.signatures &&
        payloadPart == other.payloadPart &&
        isCompact == other.isCompact

    /**
     * Hashes the signatures.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = signatures.hashCode()

    /**
     * Shows the signatures and the size of the payload.
     *
     * @return the message as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "JwsMessage(signatures=$signatures, payload=${payload?.size ?: DETACHED}, compact=$isCompact)"

    private companion object {
        const val DETACHED: String = "detached"
    }
}
