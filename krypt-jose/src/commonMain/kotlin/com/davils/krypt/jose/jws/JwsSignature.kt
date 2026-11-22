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

import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JsonValue
import kotlinx.io.bytestring.ByteString

/**
 * One signature of a decoded JWS, not verified yet.
 *
 * @property protectedHeader the protected header.
 * @property unprotectedHeader the unprotected header, empty in the compact serialization.
 * @property signature the signature or MAC.
 * @property protectedEncoded the protected header as it came, Base64url-encoded.
 * @since 1.0.0
 */
public class JwsSignature internal constructor(
    public val protectedHeader: JsonValue.Object,
    public val unprotectedHeader: JsonValue.Object,
    public val signature: ByteString,
    internal val protectedEncoded: String,
) {
    /**
     * The JOSE header: the protected and the unprotected header together.
     *
     * @since 1.0.0
     */
    public val header: JoseHeader = JoseHeader(JsonValue.Object(protectedHeader.members + unprotectedHeader.members))

    /**
     * Compares the headers and the signature.
     *
     * @param other the other object.
     * @return true if [other] is the same signature.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwsSignature &&
        protectedEncoded == other.protectedEncoded &&
        unprotectedHeader == other.unprotectedHeader &&
        signature == other.signature

    /**
     * Hashes the signature.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = signature.hashCode()

    /**
     * Shows the header.
     *
     * @return the signature as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JwsSignature($header)"
}
