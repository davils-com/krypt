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
import com.davils.krypt.jose.jwt.JwtClaims
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.internal.CheckedJwtSvid
import kotlin.time.Instant

/**
 * A JWT-SVID that [JwtSvidValidator] validated or [JwtSvidSigner] signed.
 *
 * The token is a bearer credential: whoever holds it can present it until it expires, so [toString] never shows it.
 *
 * @property id the SPIFFE id of the subject.
 * @param audience the audiences of `aud`.
 * @property expiresAt the time of `exp`.
 * @property claims every claim of the token; claims other than `sub`, `aud` and `exp` are assertions of the trust
 *   domain of [id] only, as section 4.1 of the SPIFFE ID specification cautions.
 * @property token the compact serialization.
 * @since 1.0.0
 */
public class JwtSvid private constructor(
    public val id: SpiffeId,
    audience: List<String>,
    public val expiresAt: Instant,
    public val claims: JwtClaims,
    public val token: String,
) {
    /**
     * The audiences of `aud`.
     *
     * @since 1.0.0
     */
    public val audience: List<String> = audience.toList()

    internal constructor(checked: CheckedJwtSvid) : this(
        id = checked.id,
        audience = checked.audience,
        expiresAt = checked.expiresAt,
        claims = checked.claims,
        token = checked.token,
    )

    /**
     * Compares the tokens.
     *
     * @param other the other object.
     * @return true if [other] is the same token.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is JwtSvid && token == other.token

    /**
     * Hashes the token.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = token.hashCode()

    /**
     * Shows the id, the number of audiences and the expiry, never the token.
     *
     * @return the SVID as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "JwtSvid($id, audiences=${audience.size}, expiresAt=$expiresAt, token=${SafeText.REDACTED})"
}
