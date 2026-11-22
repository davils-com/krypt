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
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.JwtAuthority
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.TrustAnchor

internal class BundleWriter(private val keys: JsonWebKeys) {
    fun bundle(bundle: TrustBundle): JsonValue.Object {
        val x509 = bundle.x509Authorities.map { certificate -> x509Of(certificate) }
        val jwt = bundle.jwtAuthorities.map { authority -> jwtOf(authority) }
        val members = listOfNotNull(
            bundle.sequence?.let { sequence -> BundleNames.SEQUENCE to JsonValue.Integer(sequence) },
            bundle.refreshHint?.let { hint -> BundleNames.REFRESH_HINT to JsonValue.Integer(hint.inWholeSeconds) },
            BundleNames.KEYS to JsonValue.Array(x509 + jwt),
        )
        return JsonValue.Object(members)
    }

    fun map(bundles: BundleSet): JsonValue.Object {
        val domains = bundles.bundles.map { found -> found.trustDomain.name to bundle(found) }
        return JsonValue.Object.of(BundleNames.TRUST_DOMAINS to JsonValue.Object(domains))
    }

    private fun x509Of(certificate: Certificate): JsonValue.Object {
        val jwk = keys.of(key = TrustAnchor.of(certificate).publicKey)
        val chain = JsonValue.Array(listOf(JsonValue.Text(Base64.encode(certificate.encoded))))
        val members = keys.members(jwk).members
        val own = listOf(BundleNames.USE to text(BundleNames.X509_SVID), BundleNames.CHAIN to chain)
        return JsonValue.Object(members + own)
    }

    private fun jwtOf(authority: JwtAuthority): JsonValue.Object {
        val jwk = keys.of(key = authority.publicKey, keyId = authority.keyId)
        val members = keys.members(jwk).members
        return JsonValue.Object(members + (BundleNames.USE to text(BundleNames.JWT_SVID)))
    }

    private fun text(value: String): JsonValue.Text = JsonValue.Text(value)
}
