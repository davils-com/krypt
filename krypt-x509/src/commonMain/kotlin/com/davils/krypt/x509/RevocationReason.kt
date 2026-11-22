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

package com.davils.krypt.x509

/**
 * Why a certificate was revoked, by RFC 5280: the code of a revocation list entry and the bit of a distribution point.
 *
 * @property code the value of CRLReason.
 * @property bit the bit of ReasonFlags, or null for a reason that has none.
 * @since 1.0.0
 */
public enum class RevocationReason(public val code: Int, public val bit: Int?) {
    /**
     * No reason given.
     *
     * @since 1.0.0
     */
    Unspecified(code = 0, bit = null),

    /**
     * The private key of the subject was compromised.
     *
     * @since 1.0.0
     */
    KeyCompromise(code = 1, bit = 1),

    /**
     * The private key of a certificate authority was compromised.
     *
     * @since 1.0.0
     */
    CaCompromise(code = 2, bit = 2),

    /**
     * The subject left the organization.
     *
     * @since 1.0.0
     */
    AffiliationChanged(code = 3, bit = 3),

    /**
     * The certificate was replaced.
     *
     * @since 1.0.0
     */
    Superseded(code = 4, bit = 4),

    /**
     * The certificate is no longer needed.
     *
     * @since 1.0.0
     */
    CessationOfOperation(code = 5, bit = 5),

    /**
     * The certificate is suspended for now.
     *
     * @since 1.0.0
     */
    CertificateHold(code = 6, bit = 6),

    /**
     * A suspension is lifted, in a delta revocation list only.
     *
     * @since 1.0.0
     */
    RemoveFromCrl(code = 8, bit = null),

    /**
     * A privilege of the subject was withdrawn.
     *
     * @since 1.0.0
     */
    PrivilegeWithdrawn(code = 9, bit = 7),

    /**
     * The key of an attribute authority was compromised.
     *
     * @since 1.0.0
     */
    AaCompromise(code = 10, bit = 8),
    ;

    internal companion object {
        fun ofCode(code: Int): RevocationReason? = entries.firstOrNull { reason -> reason.code == code }
    }
}
