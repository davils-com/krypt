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

package com.davils.krypt.tls.fixture

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.authority.store.AuthorityRepository
import com.davils.krypt.authority.store.Revocation
import com.davils.krypt.x509.Certificate

internal class MemoryRepository : AuthorityRepository {
    private val issued: MutableList<Certificate> = mutableListOf()

    private val revoked: MutableList<Revocation> = mutableListOf()

    private var crlNumber: Long = 0L

    override suspend fun record(certificate: Certificate): Boolean {
        val isNew = issued.none { found -> found.serialNumber == certificate.serialNumber }
        if (isNew) issued += certificate
        return isNew
    }

    override suspend fun find(serialNumber: DerInteger): Certificate? =
        issued.firstOrNull { found -> found.serialNumber == serialNumber }

    override suspend fun revoke(revocation: Revocation): Boolean {
        val isNew = revocation(revocation.serialNumber) == null
        if (isNew) revoked += revocation
        return isNew
    }

    override suspend fun revocation(serialNumber: DerInteger): Revocation? =
        revoked.firstOrNull { found -> found.serialNumber == serialNumber }

    override suspend fun revocations(): List<Revocation> = revoked.toList()

    override suspend fun nextCrlNumber(): Long {
        crlNumber += 1
        return crlNumber
    }
}
