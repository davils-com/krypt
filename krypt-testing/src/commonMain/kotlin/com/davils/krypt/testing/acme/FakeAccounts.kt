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

package com.davils.krypt.testing.acme

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import kotlinx.io.bytestring.ByteString

internal class FakeAccounts(private val state: FakeState, private val requests: FakeRequests) {
    suspend fun newAccount(request: SignedRequest): FakeReply {
        val jwk = present(request.jwk)
        val thumbprint = thumbprintOf(jwk)
        val existing = state.accounts.values.firstOrNull { account -> account.thumbprint == thumbprint }
        if (existing != null) return reply(account = existing, status = FakeReply.OK)
        val payload = request.body
        refuseUnless(condition = !payload.isTrue(ONLY_RETURN_EXISTING), type = AcmeProblemType.AccountDoesNotExist)
        checkBinding(binding = payload.objectOf(BINDING), jwk = jwk, url = request.url)
        val id = state.nextId()
        val account = FakeAccount(
            id = id,
            url = state.url(kind = ACCOUNT_PATH, id = id),
            key = request.key,
            thumbprint = thumbprint,
            contacts = contactsOf(payload),
            status = VALID,
        )
        state.accounts[id] = account
        return reply(account = account, status = FakeReply.CREATED)
    }

    fun account(request: SignedRequest, id: Int?): FakeReply {
        val account = state.found(records = state.accounts, id = id)
        refuseUnless(condition = request.accountId == account.id, type = AcmeProblemType.Unauthorized)
        val payload = request.body
        val status = payload.textOf(STATUS) ?: account.status
        refuseUnless(status in STATUSES)
        val contacts = contactsOf(payload).takeIf { CONTACT in payload } ?: account.contacts
        val updated = account.copy(contacts = contacts, status = status)
        state.accounts[account.id] = updated
        return reply(account = updated, status = FakeReply.OK)
    }

    suspend fun keyChange(request: SignedRequest): FakeReply {
        val account = present(request.account)
        val inner = present(request.payload)
        val newJwk = present(requests.headerOf(inner).objectOf(FakeRequests.JWK))
        val newKey = requests.publicKeyOf(newJwk)
        val payload = requests.verifyInner(
            body = inner,
            url = request.url,
            key = JoseKey.Public(newKey),
            algorithms = FakeRequests.SIGNING,
        )
        val oldKey = present(payload.objectOf(OLD_KEY))
        val isAccount = payload.textOf(ACCOUNT) == account.url
        refuseUnless(condition = isAccount, type = AcmeProblemType.Unauthorized)
        refuseUnless(condition = thumbprintOf(oldKey) == account.thumbprint, type = AcmeProblemType.Unauthorized)
        val thumbprint = thumbprintOf(newJwk)
        val isFree = state.accounts.values.none { found -> found.thumbprint == thumbprint }
        refuseUnless(condition = isFree, status = FakeReply.CONFLICT)
        val updated = account.copy(key = newKey, thumbprint = thumbprint)
        state.accounts[account.id] = updated
        return reply(account = updated, status = FakeReply.OK)
    }

    private suspend fun checkBinding(binding: JsonValue.Object?, jwk: JsonValue.Object, url: String) {
        if (state.externalAccounts.isEmpty()) return
        val found = present(value = binding, type = AcmeProblemType.ExternalAccountRequired)
        val keyId = requests.headerOf(found).textOf(FakeRequests.KEY_ID)
        val key = present(value = state.externalAccounts[keyId], type = AcmeProblemType.Unauthorized)
        val payload = requests.verifyInner(
            body = found,
            url = url,
            key = JoseKey.Secret(key),
            algorithms = FakeRequests.MAC,
        )
        refuseUnless(condition = payload == jwk, type = AcmeProblemType.Unauthorized)
    }

    private suspend fun thumbprintOf(jwk: JsonValue.Object): ByteString {
        val decoded = state.keys.decode(jwk.encode()).getOrNull()
        return state.keys.thumbprint(present(value = decoded, type = AcmeProblemType.BadPublicKey))
    }

    private fun contactsOf(payload: JsonValue.Object): List<String> = payload.itemsOf(CONTACT).map { item ->
        present(value = item.textOrNull(), type = AcmeProblemType.InvalidContact)
    }

    private fun reply(account: FakeAccount, status: Int): FakeReply {
        val body = json(
            STATUS to text(account.status),
            CONTACT to texts(account.contacts),
            ORDERS to text(state.url(kind = "orders", id = account.id)),
        )
        return FakeReply.json(json = body, status = status, location = account.url)
    }

    private companion object {
        const val ACCOUNT_PATH: String = "account"
        const val ONLY_RETURN_EXISTING: String = "onlyReturnExisting"
        const val BINDING: String = "externalAccountBinding"
        const val CONTACT: String = "contact"
        const val STATUS: String = "status"
        const val ORDERS: String = "orders"
        const val ACCOUNT: String = "account"
        const val OLD_KEY: String = "oldKey"
        const val VALID: String = "valid"
        val STATUSES: Set<String> = setOf(VALID, "deactivated")
    }
}
