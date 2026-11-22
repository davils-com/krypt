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
import com.davils.krypt.x509.path.PathValidation

/**
 * A signer whose signature verified.
 *
 * @property signer the signer.
 * @property certificate the certificate whose key verified the signature.
 * @property path the valid path to a trust anchor, or null if no path validator was given.
 * @since 1.0.0
 */
public class VerifiedSigner internal constructor(
    public val signer: SignerInfo,
    public val certificate: Certificate,
    public val path: PathValidation.Valid?,
) {
    /**
     * Compares the signer, the certificate and the path.
     *
     * @param other the other object.
     * @return true if [other] is the same result.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is VerifiedSigner &&
        listOf(
            signer,
            certificate,
            path,
        ) == listOf(other.signer, other.certificate, other.path)

    /**
     * Hashes the signer and the certificate.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(signer, certificate).hashCode()

    /**
     * Shows the signer and the subject of its certificate.
     *
     * @return the result as text.
     * @since 1.0.0
     */
    override fun toString(): String = "VerifiedSigner($signer, ${certificate.subject})"
}
