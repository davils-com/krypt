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
        return opened.mapFailure { failure -> CwtFailure.valueOf(failure.name) }.flatMap { claims ->
            val refused = refusalOf(claims, validation)
            refused?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(claims)
        }
    }

    private suspend fun claimsOf(encoded: ByteString, keys: List<CoseKey>, validation: CwtValidation): CwtClaims {
        var item = codec.item(encoded)
        var layers = 0
        var claims: CwtClaims? = null
        while (claims == null) {
            layers += 1
            ensure(layers <= Cwt.MAXIMUM_LAYERS, CoseFailure.Malformed)
            val content = codec.item(contentOf(messageOf(item, isOuter = layers == 1, validation), keys, validation))
            val isNested = content.tagOrNull() != null
            val map = content.mapOrNull()
            claims = map?.let { found -> present(CwtClaims.ofOrNull(found), CoseFailure.Malformed) }
            ensure(claims != null || isNested, CoseFailure.Malformed)
            item = content
        }
        return claims
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

    private suspend fun contentOf(message: CoseMessage, keys: List<CoseKey>, validation: CwtValidation): ByteString {
        val algorithms = validation.algorithms
        val outcome = when (message) {
            is CoseSign1 -> cose.verify(message = message, keys = keys, algorithms = algorithms)
            is CoseSign -> cose.verify(message = message, keys = keys, algorithms = algorithms).map { message.payload }
            is CoseMac0 -> cose.verify(message = message, keys = keys, algorithms = algorithms)
            is CoseMac -> cose.verify(message = message, keys = keys, algorithms = algorithms)
            is CoseEncrypt0 -> cose.decrypt(message = message, keys = keys, algorithms = algorithms)
            is CoseEncrypt -> cose.decrypt(message = message, keys = keys, algorithms = algorithms)
        }
        val content = outcome.getOrElse { failure -> CoseException.refuse(failure) }
        return present(content, CoseFailure.Malformed)
    }

    private fun refusalOf(claims: CwtClaims, validation: CwtValidation): CwtFailure? {
        val clock = cose.crypto.environment.clock
        val now = validation.at ?: clock.now()
        val skew = validation.skew
        val issuer = validation.issuer
        val audience = validation.audience
        val expiration = claims.expiration
        val checks = listOf(
            CwtFailure.MissingClaim to validation.requiredClaims.any { key -> claims[key] == null },
            CwtFailure.WrongIssuer to (issuer != null && claims.issuer != issuer),
            CwtFailure.WrongAudience to (audience != null && audience !in claims.audience),
            CwtFailure.Expired to (expiration != null && expiration <= now - skew),
            CwtFailure.NotYetValid to isBefore(first = now + skew, second = claims.notBefore),
            CwtFailure.IssuedInFuture to isBefore(first = now + skew, second = claims.issuedAt),
        )
        return checks.firstOrNull { check -> check.second }?.first
    }

    private fun isBefore(first: Instant, second: Instant?): Boolean = second != null && first < second
}
