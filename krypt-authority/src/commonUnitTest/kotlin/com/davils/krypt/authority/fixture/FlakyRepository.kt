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

package com.davils.krypt.authority.fixture

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.authority.store.AuthorityRepository
import com.davils.krypt.authority.store.Revocation
import com.davils.krypt.x509.Certificate
import kotlinx.coroutines.CompletableDeferred

internal class FlakyRepository(private val inner: MemoryRepository = MemoryRepository()) : AuthorityRepository {
    var gate: CompletableDeferred<Unit> = CompletableDeferred(Unit)

    val failing: MutableSet<String> = mutableSetOf()

    override suspend fun record(certificate: Certificate): Boolean {
        fail(RECORD)
        return inner.record(certificate)
    }

    override suspend fun find(serialNumber: DerInteger): Certificate? {
        fail(FIND)
        return inner.find(serialNumber)
    }

    override suspend fun revoke(revocation: Revocation): Boolean {
        fail(REVOKE)
        gate.await()
        return inner.revoke(revocation)
    }

    override suspend fun revocation(serialNumber: DerInteger): Revocation? = inner.revocation(serialNumber)

    override suspend fun revocations(): List<Revocation> {
        fail(LIST)
        return inner.revocations()
    }

    override suspend fun nextCrlNumber(): Long {
        fail(NUMBER)
        return inner.nextCrlNumber()
    }

    private fun fail(operation: String) {
        check(operation !in failing) { "repository down" }
    }

    companion object {
        const val RECORD: String = "record"
        const val FIND: String = "find"
        const val REVOKE: String = "revoke"
        const val LIST: String = "list"
        const val NUMBER: String = "number"
    }
}
