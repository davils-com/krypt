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

package com.davils.krypt.x509.extension

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.x509.name.GeneralName
import kotlinx.io.bytestring.ByteString

/**
 * The authority key identifier: what identifies the key that signed a certificate or a revocation list.
 *
 * @property keyIdentifier the key identifier of the issuer, or null.
 * @property issuer the names of the issuer of the issuer, or an empty list.
 * @property serialNumber the serial number of the certificate of the issuer, or null.
 * @constructor Holds the identifier.
 * @since 1.0.0
 */
public class AuthorityKeyIdentifier(
    public val keyIdentifier: ByteString?,
    public val issuer: List<GeneralName> = emptyList(),
    public val serialNumber: DerInteger? = null,
) {
    private val shown: String? = keyIdentifier?.let { found -> Hex.encode(found) }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same identifier.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AuthorityKeyIdentifier &&
        listOf(keyIdentifier, issuer, serialNumber) == listOf(other.keyIdentifier, other.issuer, other.serialNumber)

    /**
     * Hashes the key identifier.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = keyIdentifier.hashCode()

    /**
     * Shows the key identifier in hex.
     *
     * @return the identifier as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AuthorityKeyIdentifier(${shown ?: "none"})"
}
