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

package com.davils.krypt.authority

import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName
import kotlin.time.Duration

/**
 * What a certificate shall say: its subject, its key, its profile and its names.
 *
 * @property subject the distinguished name of the subject; it may be empty when [names] name the subject.
 * @property publicKey the key of the subject.
 * @property profile what the certificate is for.
 * @param names the subject alternative names.
 * @property validity how long the certificate is valid, or null for the longest the profile and the policy allow.
 * @property nameConstraints the constraints of an authority certificate, or null.
 * @constructor Creates the request.
 * @since 1.0.0
 */
public class IssuanceRequest(
    public val subject: DistinguishedName,
    public val publicKey: PublicKey,
    public val profile: CertificateProfile,
    names: List<GeneralName> = emptyList(),
    public val validity: Duration? = null,
    public val nameConstraints: NameConstraints? = null,
) {
    /**
     * The subject alternative names.
     *
     * @since 1.0.0
     */
    public val names: List<GeneralName> = names.toList()

    /**
     * Compares every field.
     *
     * @param other the other object.
     * @return true if [other] asks for the same certificate.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is IssuanceRequest && values() == other.values()

    /**
     * Hashes every field.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values().hashCode()

    /**
     * Shows the subject, the profile and the names.
     *
     * @return the request as text.
     * @since 1.0.0
     */
    override fun toString(): String = "IssuanceRequest($subject, ${profile.name}, names=$names)"

    private fun values(): List<Any?> = listOf(subject, publicKey, profile, names, validity, nameConstraints)
}
