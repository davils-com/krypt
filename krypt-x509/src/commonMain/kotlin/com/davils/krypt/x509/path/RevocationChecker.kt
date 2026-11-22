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

package com.davils.krypt.x509.path

import com.davils.krypt.x509.Certificate
import kotlin.time.Instant

/**
 * Tells the revocation status of a certificate on a path, such as by revocation lists or OCSP; the application
 * fetches what is needed, krypt never opens a connection.
 *
 * @since 1.0.0
 */
public fun interface RevocationChecker {
    /**
     * Returns the status of [certificate] at [at].
     *
     * @param certificate the certificate.
     * @param issuer the certificate of its issuer, or null if the issuer is a trust anchor without a certificate.
     * @param anchor the anchor of the path.
     * @param at the time of validation.
     * @return the status.
     * @since 1.0.0
     */
    public suspend fun check(
        certificate: Certificate,
        issuer: Certificate?,
        anchor: TrustAnchor,
        at: Instant,
    ): RevocationStatus
}
