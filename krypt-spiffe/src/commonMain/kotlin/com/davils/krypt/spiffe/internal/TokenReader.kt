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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.spiffe.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.jwt.JwtSvidFailure

internal class TokenReader(
    private val jws: Jws,
    private val keys: JsonWebKeys,
    private val limits: SpiffeLimits,
    private val algorithms: Set<JwsAlgorithm>,
) {
    fun read(token: String): UnverifiedToken {
        refuseUnless(token.length <= limits.maximumTokenBytes, JwtSvidFailure.LimitExceeded)
        refuseUnless(token.count { char -> char == DOT } == SIGNED_DOTS, JwtSvidFailure.Malformed)
        val message = jws.decode(token).getOrNull() ?: refuse(JwtSvidFailure.Malformed)
        refuseUnless(message.isCompact && message.isPayloadEncoded, JwtSvidFailure.Malformed)
        val signature = message.signatures.single()
        val members = signature.protectedHeader
        refuseUnless(members.names.all { name -> name in HEADERS }, JwtSvidFailure.UnsupportedHeader)
        val header = JoseHeader(members)
        val algorithm = JwsAlgorithm.of(header.algorithm.orEmpty())?.takeIf { found -> found in algorithms }
            ?: refuse(JwtSvidFailure.UnsupportedAlgorithm)
        val type = header.type
        refuseUnless(type == null || type in TYPES, JwtSvidFailure.WrongType)
        val keyId = header.keyId ?: refuse(JwtSvidFailure.MissingKeyId)
        val payload = message.payload ?: refuse(JwtSvidFailure.Malformed)
        val text = payload.toByteArray().decodeToString()
        val claims = keys.parse(text).getOrNull() ?: refuse(JwtSvidFailure.Malformed)
        return UnverifiedToken(id = subjectOf(claims), algorithm = algorithm, keyId = keyId)
    }

    private fun subjectOf(claims: JsonValue.Object): SpiffeId {
        val subject = claims[SUBJECT]
        if (subject !is JsonValue.Text) refuse(JwtSvidFailure.InvalidSubject)
        return SpiffeId.parse(subject.value).getOrNull() ?: refuse(JwtSvidFailure.InvalidSubject)
    }

    private companion object {
        const val DOT: Char = '.'
        const val SIGNED_DOTS: Int = 2
        const val SUBJECT: String = "sub"
        val HEADERS: Set<String> = setOf("alg", "kid", "typ")
        val TYPES: Set<String> = setOf("JWT", "JOSE")
    }
}
