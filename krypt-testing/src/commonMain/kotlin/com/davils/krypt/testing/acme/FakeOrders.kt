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

import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.IdentifierType
import com.davils.krypt.jose.JsonValue

internal class FakeOrders(private val state: FakeState) {
    fun newOrder(request: SignedRequest): FakeReply {
        val account = present(request.account)
        val payload = request.body
        val identifiers = payload.itemsOf(IDENTIFIERS).map { item -> identifierOf(item) }
        refuseUnless(identifiers.isNotEmpty())
        val replaces = payload.textOf(REPLACES)
        if (replaces != null) replace(identifier = replaces, accountId = account.id)
        val id = state.nextId()
        val order = FakeOrder(
            id = id,
            accountId = account.id,
            identifiers = identifiers,
            authorizationIds = identifiers.map { identifier -> newAuthorization(account.id, identifier) },
            status = PENDING,
            replaces = replaces,
            notBefore = payload.textOf(NOT_BEFORE),
            notAfter = payload.textOf(NOT_AFTER),
        )
        state.orders[id] = order
        return FakeReply.json(json = orderJson(order), status = FakeReply.CREATED, location = orderUrl(id))
    }

    fun order(request: SignedRequest, id: Int?): FakeReply {
        val order = owned(record = state.found(state.orders, id), owner = { found -> found.accountId }, request)
        val isProcessing = order.status == PROCESSING
        val current = when (isProcessing) {
            true -> order.copy(polls = order.polls - 1, status = statusAfterPoll(order))
            false -> order
        }
        state.orders[order.id] = current
        val retry = listOfNotNull((RETRY_AFTER to "0").takeIf { isProcessing })
        val reply = FakeReply.json(orderJson(current))
        return reply.copy(headers = reply.headers + retry)
    }

    fun authorization(request: SignedRequest, id: Int?): FakeReply {
        val record = state.found(state.authorizations, id)
        val authorization = owned(record = record, owner = { found -> found.accountId }, request = request)
        val status = request.body.textOf(STATUS) ?: authorization.status
        refuseUnless(status in setOf(authorization.status, DEACTIVATED))
        val updated = authorization.copy(status = status)
        state.authorizations[authorization.id] = updated
        return FakeReply.json(authorizationJson(updated))
    }

    fun challenge(request: SignedRequest, id: Int?): FakeReply {
        val challenge = state.found(state.challenges, id)
        val authorization = state.found(state.authorizations, challenge.authorizationId)
        owned(record = authorization, owner = { found -> found.accountId }, request = request)
        if (!request.isPostAsGet) respond(challenge = challenge, authorization = authorization)
        return FakeReply.json(challengeJson(state.found(state.challenges, id)))
    }

    private fun respond(challenge: FakeChallenge, authorization: FakeAuthorization) {
        refuseUnless(condition = authorization.status == PENDING, status = FakeReply.FORBIDDEN)
        state.challenges[challenge.id] = challenge.copy(status = VALID)
        state.authorizations[authorization.id] = authorization.copy(status = VALID)
        val orders = state.orders.values.filter { order -> authorization.id in order.authorizationIds }
        orders.forEach { order ->
            val isReady = order.authorizationIds.all { found ->
                state.found(state.authorizations, found).status == VALID
            }
            if (isReady) state.orders[order.id] = order.copy(status = READY)
        }
    }

    private fun replace(identifier: String, accountId: Int) {
        val replaced = state.certificates.values.firstOrNull { found -> found.identifier == identifier }
        val certificate = present(replaced)
        refuseUnless(condition = certificate.accountId == accountId, type = AcmeProblemType.Unauthorized)
        val type = AcmeProblemType.AlreadyReplaced
        refuseUnless(condition = !certificate.isReplaced, type = type, status = FakeReply.CONFLICT)
        state.certificates[certificate.id] = certificate.copy(isReplaced = true)
    }

    private fun newAuthorization(accountId: Int, identifier: AcmeIdentifier): Int {
        val id = state.nextId()
        val bare = AcmeIdentifier(type = identifier.type, value = identifier.value.removePrefix(WILDCARD))
        val types = when (identifier.isWildcard) {
            true -> listOf(DNS_01)
            false -> CHALLENGE_TYPES
        }
        val challengeIds = types.map { type ->
            val challengeId = state.nextId()
            val challenge = FakeChallenge(
                id = challengeId,
                authorizationId = id,
                type = type,
                token = state.token(),
                status = PENDING,
            )
            state.challenges[challengeId] = challenge
            challengeId
        }
        state.authorizations[id] = FakeAuthorization(
            id = id,
            accountId = accountId,
            identifier = bare,
            isWildcard = identifier.isWildcard,
            status = PENDING,
            challengeIds = challengeIds,
        )
        return id
    }

    private fun statusAfterPoll(order: FakeOrder): String = when (order.polls <= 1) {
        true -> VALID
        false -> PROCESSING
    }

    fun orderJson(order: FakeOrder): JsonValue.Object {
        val certificate = order.certificateId.takeIf { order.status == VALID }
        return json(
            STATUS to text(order.status),
            IDENTIFIERS to JsonValue.Array(order.identifiers.map { identifier -> identifierJson(identifier) }),
            AUTHORIZATIONS to texts(order.authorizationIds.map { found -> state.url(kind = AUTHZ, id = found) }),
            FINALIZE to text(state.url(kind = FINALIZE, id = order.id)),
            CERTIFICATE to text(certificate?.let { found -> certificateUrl(found) }),
            NOT_BEFORE to text(order.notBefore),
            NOT_AFTER to text(order.notAfter),
            REPLACES to text(order.replaces),
        )
    }

    fun orderUrl(id: Int): String = state.url(kind = ORDER, id = id)

    fun certificateUrl(id: Int): String = state.url(kind = CERT, id = id)

    fun <T> owned(record: T, owner: (T) -> Int, request: SignedRequest): T {
        refuseUnless(condition = request.accountId == owner(record), type = AcmeProblemType.Unauthorized)
        return record
    }

    private fun authorizationJson(authorization: FakeAuthorization): JsonValue.Object = json(
        IDENTIFIER to identifierJson(authorization.identifier),
        STATUS to text(authorization.status),
        CHALLENGES to JsonValue.Array(
            authorization.challengeIds.map { id -> challengeJson(state.found(state.challenges, id)) },
        ),
        WILDCARD_MEMBER to JsonValue.Bool(true).takeIf { authorization.isWildcard },
    )

    private fun challengeJson(challenge: FakeChallenge): JsonValue.Object = json(
        TYPE to text(challenge.type),
        URL to text(state.url(kind = CHALL, id = challenge.id)),
        STATUS to text(challenge.status),
        TOKEN to text(challenge.token),
    )

    private fun identifierJson(identifier: AcmeIdentifier): JsonValue.Object =
        json(TYPE to text(identifier.type.typeName), VALUE to text(identifier.value))

    private fun identifierOf(item: JsonValue): AcmeIdentifier {
        val members = present(item as? JsonValue.Object)
        val type = present(value = IdentifierType.of(present(members.textOf(TYPE))), type = UNSUPPORTED)
        val value = present(members.textOf(VALUE))
        val identifier = runCatching { AcmeIdentifier(type = type, value = value) }
        return present(value = identifier.getOrNull(), type = AcmeProblemType.RejectedIdentifier)
    }

    companion object {
        const val PENDING: String = "pending"
        const val READY: String = "ready"
        const val PROCESSING: String = "processing"
        const val VALID: String = "valid"
        const val DEACTIVATED: String = "deactivated"
        const val STATUS: String = "status"
        const val ORDER: String = "order"
        const val AUTHZ: String = "authz"
        const val CHALL: String = "chall"
        const val FINALIZE: String = "finalize"
        const val CERT: String = "cert"
        const val RETRY_AFTER: String = "Retry-After"
        private const val IDENTIFIERS: String = "identifiers"
        private const val IDENTIFIER: String = "identifier"
        private const val AUTHORIZATIONS: String = "authorizations"
        private const val CERTIFICATE: String = "certificate"
        private const val CHALLENGES: String = "challenges"
        private const val NOT_BEFORE: String = "notBefore"
        private const val NOT_AFTER: String = "notAfter"
        private const val REPLACES: String = "replaces"
        private const val WILDCARD_MEMBER: String = "wildcard"
        private const val WILDCARD: String = "*."
        private const val TYPE: String = "type"
        private const val VALUE: String = "value"
        private const val URL: String = "url"
        private const val TOKEN: String = "token"
        private const val DNS_01: String = "dns-01"
        private val UNSUPPORTED: AcmeProblemType = AcmeProblemType.UnsupportedIdentifier
        private val CHALLENGE_TYPES: List<String> = listOf("http-01", DNS_01, "tls-alpn-01")
    }
}
