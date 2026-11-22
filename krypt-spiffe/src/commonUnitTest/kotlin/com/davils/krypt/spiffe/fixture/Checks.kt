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

package com.davils.krypt.spiffe.fixture

import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.bundle.BundleFailure
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.bundle.TrustBundles
import com.davils.krypt.spiffe.jwt.JwtSvid
import com.davils.krypt.spiffe.jwt.JwtSvidFailure
import com.davils.krypt.spiffe.jwt.JwtSvidValidator
import com.davils.krypt.spiffe.x509.X509SvidFailure
import com.davils.krypt.spiffe.x509.X509SvidValidator
import com.davils.krypt.x509.Certificate

internal const val AUDIENCE: String = "reports"

internal fun bundlesOf(vararg roots: Certificate): BundleSet = BundleSet(listOf(TrustBundle(domain, roots.toList())))

internal suspend fun X509SvidValidator.failureOf(chain: List<Certificate>): X509SvidFailure? =
    validate(chain = chain).failure()

internal suspend fun X509SvidValidator.idOf(chain: List<Certificate>): SpiffeId {
    val validated = validate(chain = chain).value()
    return validated.id
}

internal suspend fun JwtSvidValidator.failureOf(token: String, audience: String = AUDIENCE): JwtSvidFailure? =
    validate(token = token, audience = audience).failure()

internal suspend fun JwtSvidValidator.svidOf(token: String, audience: String = AUDIENCE): JwtSvid =
    validate(token = token, audience = audience).value()

internal fun TrustBundles.failureOf(text: String): BundleFailure? = decode(trustDomain = domain, text = text).failure()

internal fun TrustBundles.read(text: String): TrustBundle = decode(trustDomain = domain, text = text).value()
