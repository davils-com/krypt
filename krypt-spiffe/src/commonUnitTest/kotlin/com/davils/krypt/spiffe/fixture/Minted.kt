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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.JwtAuthority
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.jwt.JwtSvidSigner
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

internal class Minted(val pair: KeyPair, val signer: JwtSvidSigner, val bundles: BundleSet) {
    suspend fun token(
        subject: SpiffeId = workload,
        audience: List<String> = listOf(AUDIENCE),
        lifetime: Duration = 5.minutes,
    ): String {
        val svid = signer.sign(subject = subject, audience = audience, lifetime = lifetime)
        return svid.token
    }

    companion object {
        const val KEY_ID: String = "key-1"

        suspend fun of(
            type: KeyType = KeyType.P256,
            algorithm: JwsAlgorithm = JwsAlgorithm.ES256,
            engine: Crypto = crypto,
        ): Minted {
            val pair = engine.keys.generate(type)
            val signer = JwtSvidSigner(crypto = engine, key = pair.privateKey, keyId = KEY_ID, algorithm = algorithm)
            val bundle = TrustBundle(domain, jwtAuthorities = listOf(JwtAuthority(KEY_ID, pair.publicKey)))
            return Minted(pair, signer, BundleSet(listOf(bundle)))
        }
    }
}
