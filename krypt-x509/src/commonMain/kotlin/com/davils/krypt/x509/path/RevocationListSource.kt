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
import com.davils.krypt.x509.crl.RevocationList

/**
 * Provides the revocation lists that may cover a certificate, such as those of its distribution points, from a cache
 * or a download of the application.
 *
 * @since 1.0.0
 */
public fun interface RevocationListSource {
    /**
     * Returns the lists that may cover [certificate].
     *
     * @param certificate the certificate.
     * @return the lists, possibly from an attacker; krypt checks their signatures, their issuers and their freshness.
     * @since 1.0.0
     */
    public suspend fun revocationLists(certificate: Certificate): List<RevocationList>
}
