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

package com.davils.krypt.spiffe.jwt

import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jwt.Jwt
import com.davils.krypt.jose.jwt.JwtValidator
import com.davils.krypt.jose.jwt.jwtValidator
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.internal.CheckedJwtSvid
import com.davils.krypt.spiffe.internal.TokenReader
import com.davils.krypt.spiffe.internal.checking
import com.davils.krypt.spiffe.internal.refuse
import com.davils.krypt.spiffe.source.BundleSource
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Validates JWT-SVIDs by the JWT-SVID specification, over the JWS and JWT of krypt-jose.
 *
 * A token must be a compact JWS of at most [SpiffeLimits.maximumTokenBytes] whose protected header holds only `alg`,
 * `kid` and `typ`: `alg` one of [algorithms], `kid` present, `typ` absent, `JWT` or `JOSE`. Its `sub` must be a SPIFFE
 * id; the `kid` is looked up among the JWT authorities of the bundle of the trust domain of that id, and of no other
 * trust domain. The signature is then verified with that key under the crypto policy of [crypto], `exp` is required,
 * `exp`, `nbf` and `iat` are checked against the clock of [crypto] with [clockSkew], and `aud` must name the audience
 * of the call. The validator does not track `jti`, so a token can be replayed until it expires, as section 7.1 of the
 * specification explains.
 *
 * The bundle source is foreign code: a failure of it is contained and counts as a missing bundle. The validator holds
 * no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto of the verification and its clock.
 * @param bundles the bundles of the trust domains.
 * @property clockSkew the clock skew allowed for `exp`, `nbf` and `iat`.
 * @param algorithms the algorithms accepted, a subset of [ALGORITHMS].
 * @property limits the size of a token.
 * @constructor Checks the configuration.
 * @throws IllegalArgumentException if [clockSkew] is negative or above [MAXIMUM_CLOCK_SKEW], or [algorithms] is empty
 *   or names an algorithm outside [ALGORITHMS].
 * @since 1.0.0
 */
public class JwtSvidValidator(
    public val crypto: Crypto,
    private val bundles: BundleSource,
    public val clockSkew: Duration = DEFAULT_CLOCK_SKEW,
    algorithms: Set<JwsAlgorithm> = ALGORITHMS,
    public val limits: SpiffeLimits = SpiffeLimits.Default,
) {
    /**
     * The algorithms accepted.
     *
     * @since 1.0.0
     */
    public val algorithms: Set<JwsAlgorithm> = algorithms.toSet()

    private val joseLimits = JoseLimits(
        maximumBytes = limits.maximumTokenBytes,
        maximumStringLength = limits.maximumTokenBytes,
    )

    private val jwt = Jwt(crypto = crypto, limits = joseLimits)

    private val reader = TokenReader(
        jws = Jws(crypto = crypto, limits = joseLimits),
        keys = JsonWebKeys(crypto = crypto, limits = joseLimits),
        limits = limits,
        algorithms = this.algorithms,
    )

    init {
        require(clockSkew in Duration.ZERO..MAXIMUM_CLOCK_SKEW) { "A clock skew is 0 to $MAXIMUM_CLOCK_SKEW" }
        val isPermitted = this.algorithms.isNotEmpty() && ALGORITHMS.containsAll(this.algorithms)
        require(isPermitted) { "The algorithms are RS256 to RS512, ES256 to ES512 and PS256 to PS512" }
    }

    /**
     * Validates [token] for [audience].
     *
     * @param token the compact serialization, possibly from an attacker.
     * @param audience the audience this validator identifies with, which `aud` must name.
     * @return the validated SVID, or why the token was refused.
     * @throws IllegalArgumentException if [audience] is empty.
     * @since 1.0.0
     */
    public suspend fun validate(token: String, audience: String): Outcome<JwtSvid, JwtSvidFailure> {
        require(audience.isNotEmpty()) { "An audience is not empty" }
        return checking {
            val unverified = reader.read(token)
            val id = unverified.id
            val bundle = attempted { bundles.bundle(id.trustDomain) }.getOrNull() ?: refuse(JwtSvidFailure.NoBundle)
            val authority = bundle.jwtAuthority(unverified.keyId) ?: refuse(JwtSvidFailure.KeyNotFound)
            val key = JoseKey.Public(key = authority.publicKey, keyId = authority.keyId)
            val validator = validatorOf(algorithm = unverified.algorithm, expected = audience)
            val claims = when (val validated = jwt.validate(token = token, validator = validator, keys = listOf(key))) {
                is Outcome.Success -> validated.value.claims
                is Outcome.Failure -> refuse(FAILURES[validated.failure] ?: JwtSvidFailure.Malformed)
            }
            val expiresAt = claims.expiresAt ?: refuse(JwtSvidFailure.MissingExpiration)
            val checked = CheckedJwtSvid(
                id = id,
                audience = claims.audience,
                expiresAt = expiresAt,
                claims = claims,
                token = token,
            )
            JwtSvid(checked)
        }
    }

    /**
     * Shows the algorithms, the clock skew and the limits.
     *
     * @return the validator as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "JwtSvidValidator(algorithms=${algorithms.map { found -> found.algorithmName }}, skew=$clockSkew, $limits)"

    private fun validatorOf(algorithm: JwsAlgorithm, expected: String): JwtValidator {
        val skew = clockSkew
        return jwtValidator {
            algorithms(algorithm)
            audience(expected)
            clockSkew = skew
            isExpirationRequired = true
        }
    }

    /**
     * The algorithms and the bounds of the clock skew.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The algorithms section 2.1 of the JWT-SVID specification allows that krypt-jose offers: RSASSA-PKCS1-v1_5,
         * ECDSA and RSASSA-PSS with SHA-2. Whether an algorithm is usable also depends on the crypto policy, which
         * refuses RSASSA-PKCS1-v1_5 in the `Modern` profile.
         *
         * @since 1.0.0
         */
        public val ALGORITHMS: Set<JwsAlgorithm> = setOf(
            JwsAlgorithm.RS256,
            JwsAlgorithm.RS384,
            JwsAlgorithm.RS512,
            JwsAlgorithm.ES256,
            JwsAlgorithm.ES384,
            JwsAlgorithm.ES512,
            JwsAlgorithm.PS256,
            JwsAlgorithm.PS384,
            JwsAlgorithm.PS512,
        )

        /**
         * The default clock skew.
         *
         * @since 1.0.0
         */
        public val DEFAULT_CLOCK_SKEW: Duration = 30.seconds

        /**
         * The largest clock skew.
         *
         * @since 1.0.0
         */
        public val MAXIMUM_CLOCK_SKEW: Duration = 5.minutes

        private val FAILURES: Map<JoseFailure, JwtSvidFailure> = mapOf(
            JoseFailure.BadSignature to JwtSvidFailure.BadSignature,
            JoseFailure.Expired to JwtSvidFailure.Expired,
            JoseFailure.NotYetValid to JwtSvidFailure.NotYetValid,
            JoseFailure.WrongAudience to JwtSvidFailure.WrongAudience,
            JoseFailure.MissingClaim to JwtSvidFailure.MissingExpiration,
            JoseFailure.InvalidKey to JwtSvidFailure.KeyNotFound,
            JoseFailure.KeyNotFound to JwtSvidFailure.KeyNotFound,
        )
    }
}
