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

package com.davils.krypt.cms.signed

import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.ValidationParameters

/**
 * What the verification of signed data checks besides the signatures.
 *
 * Without a [validator] krypt checks only that the signature verifies with the key of a certificate that the
 * message or the caller supplies; anybody can make such a certificate. Pass a validator to decide whom to trust.
 *
 * @param certificates certificates of the caller that may name a signer or lie on its path, besides those in
 *   the message.
 * @property validator the path validator with the caller's trust anchors, or null to check no path.
 * @property validation the parameters of the path validation, such as its time and the purpose of the signer.
 * @constructor Describes a verification.
 * @since 1.0.0
 */
public class SignatureParameters(
    certificates: List<Certificate> = emptyList(),
    public val validator: PathValidator? = null,
    public val validation: ValidationParameters = ValidationParameters(),
) {
    /**
     * Certificates of the caller that may name a signer or lie on its path, besides those in the message.
     *
     * @since 1.0.0
     */
    public val certificates: List<Certificate> = certificates.toList()

    private val values: List<Any?> get() = listOf(certificates, validator, validation)

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same verification.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SignatureParameters && values == other.values

    /**
     * Hashes every property.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the number of certificates and whether a path is validated.
     *
     * @return the parameters as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "SignatureParameters(${certificates.size} certificates, path=${validator != null})"
}
