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

package com.davils.krypt.spiffe.jwt

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jwt.Jwt
import com.davils.krypt.jose.jwt.jwtClaims
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.bundle.JwtAuthority
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * Signs JWT-SVIDs with a JWT authority of a trust domain, such as a workload that mints its own tokens or the signer
 * of a SPIFFE control plane.
 *
 * Every token is a compact JWS whose header holds only `alg`, `kid` and `typ` `JWT`, and whose claims hold `sub`,
 * `aud`, `iat`, `exp` and the extra claims of the caller. The signer never destroys the private key, which stays with
 * the caller, and never shows it.
 *
 * @property crypto the crypto of the signatures and its clock.
 * @param key the private key of the JWT authority.
 * @property keyId the key id the bundle of the trust domain publishes for the key.
 * @property algorithm the algorithm, one of [JwtSvidValidator.ALGORITHMS] that fits the key.
 * @constructor Checks the configuration.
 * @throws IllegalArgumentException if [algorithm] is not one of [JwtSvidValidator.ALGORITHMS] or [keyId] is empty or
 *   longer than [JwtAuthority.MAXIMUM_KEY_ID_LENGTH].
 * @since 1.0.0
 */
public class JwtSvidSigner(
    public val crypto: Crypto,
    private val key: PrivateKey,
    public val keyId: String,
    public val algorithm: JwsAlgorithm,
) {
    private val jwt = Jwt(crypto)

    init {
        require(algorithm in JwtSvidValidator.ALGORITHMS) { "A JWT-SVID is signed by RSA or ECDSA with SHA-2" }
        require(keyId.length in 1..JwtAuthority.MAXIMUM_KEY_ID_LENGTH) {
            "A key id has 1 to ${JwtAuthority.MAXIMUM_KEY_ID_LENGTH} characters"
        }
    }

    /**
     * Signs a JWT-SVID for [subject].
     *
     * @param subject the SPIFFE id of the workload the token asserts.
     * @param audience the audiences; one is strongly recommended, as section 7.2 of the specification explains.
     * @param lifetime how long the token is valid from now, on whole seconds, as short as possible.
     * @param claims extra claims, none of `iss`, `sub`, `aud`, `exp`, `nbf`, `iat` and `jti`.
     * @return the SVID.
     * @throws IllegalArgumentException if [audience] is empty or holds an empty audience, [lifetime] is not positive
     *   or above [MAXIMUM_LIFETIME], [claims] holds a registered claim, or the key does not fit [algorithm].
     * @throws com.davils.krypt.primitive.CryptoException if the crypto policy refuses the key or the algorithm.
     * @since 1.0.0
     */
    public suspend fun sign(
        subject: SpiffeId,
        audience: List<String>,
        lifetime: Duration,
        claims: JsonValue.Object = JsonValue.Object.Empty,
    ): JwtSvid {
        require(audience.isNotEmpty() && audience.none { name -> name.isEmpty() }) { "A JWT-SVID has audiences" }
        require(lifetime.isPositive() && lifetime <= MAXIMUM_LIFETIME) { "A lifetime is up to $MAXIMUM_LIFETIME" }
        val now = crypto.environment.clock.now()
        val expiresAt = Instant.fromEpochSeconds((now + lifetime).epochSeconds)
        val names = audience.toList()
        val built = jwtClaims {
            tokenSubject = subject.text
            this.audience = names
            issuedAt = now
            this.expiresAt = expiresAt
            claims.members.forEach { (name, value) -> claim(name = name, value = value) }
        }
        val token = jwt.sign(claims = built, key = JoseKey.Private(key = key, keyId = keyId), algorithm = algorithm)
        return JwtSvid(id = subject, audience = names, expiresAt = expiresAt, claims = built, token = token)
    }

    /**
     * Shows the key id and the algorithm, never the key.
     *
     * @return the signer as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "JwtSvidSigner(kid=${SafeText.text(keyId)}, ${algorithm.algorithmName}, key=${SafeText.REDACTED})"

    /**
     * The bounds of a token.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The longest lifetime of a token.
         *
         * @since 1.0.0
         */
        public val MAXIMUM_LIFETIME: Duration = 1.days
    }
}
