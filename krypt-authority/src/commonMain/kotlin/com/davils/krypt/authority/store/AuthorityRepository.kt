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

package com.davils.krypt.authority.store

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.x509.Certificate

/**
 * Keeps the state of a certificate authority: what it issued, what it revoked and the number of its last
 * revocation list. krypt keeps no state of its own; the application implements the repository over its database.
 *
 * Every method may be called from several coroutines at once, and [record], [revoke] and [nextCrlNumber] must be
 * atomic: two calls never both record one serial number, both revoke one certificate or get one number.
 * Exceptions are not caught by krypt.
 *
 * @since 1.0.0
 */
public interface AuthorityRepository {
    /**
     * Records an issued certificate.
     *
     * @param certificate the certificate.
     * @return false if a certificate with its serial number is already recorded; nothing is changed then.
     * @since 1.0.0
     */
    public suspend fun record(certificate: Certificate): Boolean

    /**
     * Finds an issued certificate.
     *
     * @param serialNumber the serial number.
     * @return the certificate, or null.
     * @since 1.0.0
     */
    public suspend fun find(serialNumber: DerInteger): Certificate?

    /**
     * Records a revocation.
     *
     * @param revocation the revocation.
     * @return false if the certificate is already revoked; nothing is changed then.
     * @since 1.0.0
     */
    public suspend fun revoke(revocation: Revocation): Boolean

    /**
     * Finds the revocation of a certificate.
     *
     * @param serialNumber the serial number.
     * @return the revocation, or null if the certificate is not revoked.
     * @since 1.0.0
     */
    public suspend fun revocation(serialNumber: DerInteger): Revocation?

    /**
     * Lists the revocations, for a revocation list; an expired certificate may be left out.
     *
     * @return the revocations.
     * @since 1.0.0
     */
    public suspend fun revocations(): List<Revocation>

    /**
     * Takes the next number of a revocation list, larger than every number taken before.
     *
     * @return the number.
     * @since 1.0.0
     */
    public suspend fun nextCrlNumber(): Long
}
