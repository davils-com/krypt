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
import com.davils.kore.core.collection.OrderedSet
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jwk.Jwk
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.BundleFailure
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.JwtAuthority
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.x509.Certificate
import kotlin.time.Duration.Companion.seconds

internal class BundleReader(private val keys: JsonWebKeys, private val limits: SpiffeLimits) {
    fun bundle(trustDomain: TrustDomain, text: String): TrustBundle =
        read(trustDomain = trustDomain, json = parsed(text))

    fun map(text: String): BundleSet {
        val domains = parsed(text)[BundleNames.TRUST_DOMAINS]
        if (domains !is JsonValue.Object) refuse(BundleFailure.Malformed)
        val members = domains.members
        refuseUnless(members.size <= limits.maximumTrustDomains, BundleFailure.LimitExceeded)
        val bundles = members.map { (name, value) ->
            val trustDomain = TrustDomain.parse(name).getOrNull() ?: refuse(BundleFailure.InvalidTrustDomain)
            if (value !is JsonValue.Object) refuse(BundleFailure.Malformed)
            read(trustDomain = trustDomain, json = value)
        }
        return BundleSet(bundles)
    }

    private fun parsed(text: String): JsonValue.Object {
        refuseUnless(text.length <= limits.maximumBytes, BundleFailure.LimitExceeded)
        return when (val parsed = keys.parse(text)) {
            is Outcome.Success -> parsed.value
            is Outcome.Failure -> refuse(failureOf(parsed.failure))
        }
    }

    private fun read(trustDomain: TrustDomain, json: JsonValue.Object): TrustBundle {
        val items = json[BundleNames.KEYS]
        if (items !is JsonValue.Array) refuse(BundleFailure.Malformed)
        val entries = items.items
        refuseUnless(entries.size <= limits.maximumAuthorities, BundleFailure.LimitExceeded)
        val sequence = integerOf(json = json, name = BundleNames.SEQUENCE)
        val hint = integerOf(json = json, name = BundleNames.REFRESH_HINT)
        refuseUnless(hint == null || hint <= TrustBundle.MAXIMUM_REFRESH_HINT_SECONDS, BundleFailure.Malformed)
        val objects = entries.filterIsInstance<JsonValue.Object>()
        refuseUnless(objects.size == entries.size, BundleFailure.Malformed)
        val x509Entries = objects.filter { entry -> isUse(entry = entry, use = BundleNames.X509_SVID) }
        val jwtEntries = objects.filter { entry -> isUse(entry = entry, use = BundleNames.JWT_SVID) }
        val x509 = x509Entries.mapNotNull { entry -> x509Of(entry) }
        val jwt = jwtEntries.mapNotNull { entry -> jwtOf(entry) }
        val keyIds = OrderedSet(jwt.map { authority -> authority.keyId })
        refuseUnless(keyIds.size == jwt.size, BundleFailure.DuplicateKeyId)
        return TrustBundle(
            trustDomain = trustDomain,
            x509Authorities = x509,
            jwtAuthorities = jwt,
            sequence = sequence,
            refreshHint = hint?.seconds,
        )
    }

    private fun integerOf(json: JsonValue.Object, name: String): Long? {
        val value = json[name] ?: return null
        if (value !is JsonValue.Integer || value.value < 0) refuse(BundleFailure.Malformed)
        return value.value
    }

    private fun isUse(entry: JsonValue.Object, use: String): Boolean {
        val value = entry[BundleNames.USE]
        return value is JsonValue.Text && value.value == use
    }

    private fun x509Of(entry: JsonValue.Object): Certificate? {
        val chain = entry[BundleNames.CHAIN]
        val isIgnored = chain == null || (chain is JsonValue.Array && chain.items.isEmpty())
        if (isIgnored) return null
        return jwkOf(entry)?.let { jwk ->
            val certificate = jwk.certificates.first()
            refuseUnless(certificate.publicKey != null, BundleFailure.InvalidKey)
            certificate
        }
    }

    private fun jwtOf(entry: JsonValue.Object): JwtAuthority? {
        val jwk = jwkOf(entry) ?: return null
        val keyId = jwk.keyId ?: refuse(BundleFailure.MissingKeyId)
        refuseUnless(keyId.length in 1..JwtAuthority.MAXIMUM_KEY_ID_LENGTH, BundleFailure.InvalidKey)
        val publicKey = keys.publicKey(jwk).getOrNull() ?: refuse(BundleFailure.InvalidKey)
        return JwtAuthority(keyId = keyId, publicKey = publicKey)
    }

    private fun jwkOf(entry: JsonValue.Object): Jwk? {
        val stripped = JsonValue.Object(entry.members.filter { (name, _) -> name != BundleNames.USE })
        val read = keys.read(stripped)
        val failure = read.failureOrNull()
        refuseUnless(failure == null || failure == JoseFailure.UnsupportedAlgorithm, BundleFailure.InvalidKey)
        return read.getOrNull()?.let { jwk -> publicOnly(jwk) }
    }

    private fun publicOnly(jwk: Jwk): Jwk {
        if (jwk.isPrivate) {
            jwk.destroy()
            refuse(BundleFailure.InvalidKey)
        }
        return jwk
    }

    private fun failureOf(failure: JoseFailure): BundleFailure =
        BundleFailure.LimitExceeded.takeIf { failure == JoseFailure.LimitExceeded } ?: BundleFailure.Malformed
}
