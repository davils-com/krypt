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

package com.davils.krypt.keystore.pkcs12

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.x509.Certificate

/**
 * A certificate of its own in a PKCS #12 file, such as a trust anchor.
 *
 * @property certificate the certificate.
 * @property alias the friendly name, or null.
 * @property isTrusted whether the file marks the certificate as trusted for every purpose, as the key stores of the
 *   JDK do for their trusted certificate entries.
 * @constructor Creates the entry.
 * @since 1.0.0
 */
public class CertificateEntry(
    public val certificate: Certificate,
    public val alias: String? = null,
    public val isTrusted: Boolean = false,
) {
    /**
     * Compares every field.
     *
     * @param other the other object.
     * @return true if [other] is the same entry.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CertificateEntry &&
        listOf(certificate, alias, isTrusted) == listOf(other.certificate, other.alias, other.isTrusted)

    /**
     * Hashes every field.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(certificate, alias, isTrusted).hashCode()

    /**
     * Shows the alias, the subject and the trust.
     *
     * @return the entry as text.
     * @since 1.0.0
     */
    @OptIn(DavilsInternal::class)
    override fun toString(): String {
        val shown = SafeText.text(alias ?: "none")
        return "CertificateEntry($shown, ${certificate.subject}, trusted=$isTrusted)"
    }
}
