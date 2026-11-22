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

package com.davils.krypt.cose.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrElse
import com.davils.kore.core.outcome.map
import com.davils.kore.core.outcome.mapFailure
import com.davils.krypt.cose.Cose
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseEncrypt
import com.davils.krypt.cose.CoseEncrypt0
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseMac
import com.davils.krypt.cose.CoseMac0
import com.davils.krypt.cose.CoseMessage
import com.davils.krypt.cose.CoseSign
import com.davils.krypt.cose.CoseSign1
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cwt.Cwt
import com.davils.krypt.cose.cwt.CwtClaims
import com.davils.krypt.cose.cwt.CwtFailure
import com.davils.krypt.cose.cwt.CwtValidation
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import com.davils.krypt.cose.key.CoseKey
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal class CwtValidator(private val cose: Cose) {
    private val codec = MessageCodec(cose.limits, cose.mode)

    suspend fun validate(
        encoded: ByteString,
        keys: List<CoseKey>,
        validation: CwtValidation,
    ): Outcome<CwtClaims, CwtFailure> {
        val opened = CoseException.outcome { claimsOf(encoded, keys, validation) }
        return opened.mapFailure { failure -> CwtFailure.valueOf(failure.name) }.flatMap { found ->
            val refused = refusalOf(found, validation)
            refused?.let { failure -> Outcome.Failure(failure) } ?: Outcome.Success(found.claims)
        }
    }

    private suspend fun claimsOf(encoded: ByteString, keys: List<CoseKey>, validation: CwtValidation): Opened {
        var item = codec.item(encoded)
        var layers = 0
        var isAuthenticated = false
        var claims: CwtClaims? = null
        while (claims == null) {
            layers += 1
            ensure(layers <= Cwt.MAXIMUM_LAYERS, CoseFailure.Malformed)
            val opened = contentOf(messageOf(item, isOuter = layers == 1, validation), keys, validation)
            isAuthenticated = isAuthenticated || opened.isAuthenticated
            val content = codec.item(opened.bytes)
            val isNested = content.tagOrNull() != null
            val map = content.mapOrNull()
            claims = map?.let { found -> present(CwtClaims.ofOrNull(found), CoseFailure.Malformed) }
            ensure(claims != null || isNested, CoseFailure.Malformed)
            item = content
        }
        return Opened(claims = claims, isAuthenticated = isAuthenticated)
    }

    private fun messageOf(item: CborItem, isOuter: Boolean, validation: CwtValidation): CoseMessage {
        val tag = item.tagOrNull()
        val isCwt = tag?.number == Cwt.TAG
        val content = tag?.content
        val inner = content.takeIf { isCwt } ?: item
        ensure(!isCwt || inner.tagOrNull() != null, CoseFailure.Malformed)
        val untagged = validation.untaggedType?.takeIf { isOuter && inner.tagOrNull() == null }
        if (untagged != null) return codec.message(inner, untagged)
        return codec.message(inner)
    }

    private suspend fun contentOf(message: CoseMessage, keys: List<CoseKey>, validation: CwtValidation): Content {
        val step = stepOf(message = message, keys = keys, algorithms = validation.algorithms)
        val content = step.outcome.getOrElse { failure -> CoseException.refuse(failure) }
        return Content(bytes = present(content, CoseFailure.Malformed), isAuthenticated = step.isAuthenticated)
    }

    private suspend fun stepOf(message: CoseMessage, keys: List<CoseKey>, algorithms: Set<CoseAlgorithm>): Step =
        when (message) {
            is CoseSign1 -> Step(cose.verify(message = message, keys = keys, algorithms = algorithms))
            is CoseSign -> Step(signed(message = message, keys = keys, algorithms = algorithms))
            is CoseMac0 -> Step(cose.verify(message = message, keys = keys, algorithms = algorithms))
            is CoseMac -> withRecipients(algorithms) { allowed -> cose.verify(message, keys, allowed) }
            is CoseEncrypt0 -> Step(cose.decrypt(message = message, keys = keys, algorithms = algorithms))
            is CoseEncrypt -> withRecipients(algorithms) { allowed -> cose.decrypt(message, keys, allowed) }
        }

    private suspend fun signed(
        message: CoseSign,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
    ): Outcome<ByteString?, CoseFailure> {
        val verified = cose.verify(message = message, keys = keys, algorithms = algorithms)
        return verified.map { message.payload }
    }

    private suspend fun withRecipients(
        algorithms: Set<CoseAlgorithm>,
        open: suspend (Set<CoseAlgorithm>) -> Outcome<ByteString?, CoseFailure>,
    ): Step {
        val preShared = algorithms.filterTo(linkedSetOf()) { algorithm -> algorithm.kdf == null }
        val authenticated = open(preShared)
        val isDone = authenticated is Outcome.Success || preShared.size == algorithms.size
        if (isDone) return Step(authenticated)
        return Step(outcome = open(algorithms), isAuthenticated = false)
    }

    private fun refusalOf(opened: Opened, validation: CwtValidation): CwtFailure? {
        val claims = opened.claims
        val clock = cose.crypto.environment.clock
        val now = validation.at ?: clock.now()
        val skew = validation.skew
        val issuer = validation.issuer
        val audience = validation.audience
        val expiration = claims.expiration
        val checks = listOf(
            CwtFailure.Unauthenticated to (validation.isAuthenticationRequired && !opened.isAuthenticated),
            CwtFailure.MissingClaim to isMissing(claims, validation),
            CwtFailure.WrongIssuer to (issuer != null && claims.issuer != issuer),
            CwtFailure.WrongAudience to (audience != null && audience !in claims.audience),
            CwtFailure.Expired to (expiration != null && expiration <= now - skew),
            CwtFailure.NotYetValid to isBefore(first = now + skew, second = claims.notBefore),
            CwtFailure.IssuedInFuture to isBefore(first = now + skew, second = claims.issuedAt),
        )
        return checks.firstOrNull { check -> check.second }?.first
    }

    private fun isMissing(claims: CwtClaims, validation: CwtValidation): Boolean {
        val isExpirationMissing = validation.isExpirationRequired && claims.expiration == null
        return isExpirationMissing || validation.requiredClaims.any { key -> claims[key] == null }
    }

    private fun isBefore(first: Instant, second: Instant?): Boolean = second != null && first < second

    private data class Opened(val claims: CwtClaims, val isAuthenticated: Boolean)

    private data class Content(val bytes: ByteString, val isAuthenticated: Boolean)

    private data class Step(val outcome: Outcome<ByteString?, CoseFailure>, val isAuthenticated: Boolean = true)
}
