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

package com.davils.krypt.spiffe.bundle

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.internal.BundleReader
import com.davils.krypt.spiffe.internal.BundleWriter
import com.davils.krypt.spiffe.internal.reading

/**
 * Reads and writes SPIFFE bundles and bundle maps of the SPIFFE Trust Domain and Bundle specification: a JWK set of
 * RFC 7517 whose keys carry `use` `x509-svid` or `jwt-svid`, with `spiffe_sequence` and `spiffe_refresh_hint`.
 *
 * Reading is strict and bounded by [limits]. The JSON follows the rules of krypt-jose, a duplicate member is refused,
 * and every JWK is read by the rules of [JsonWebKeys]. As the specification demands, a key without `use`, of an
 * unknown `use` or of a key type krypt does not know is ignored, as is an `x509-svid` key without certificates; of the
 * certificates of `x5c` the first one is the authority, and it must hold the key of its JWK. A key for `x509-svid`
 * or `jwt-svid` that is otherwise invalid, private or symmetric refuses the whole bundle, as does a `jwt-svid` key
 * without `kid` or with the `kid` of another. Other members of the bundle are ignored. The sequence and the refresh
 * hint are non-negative integers up to 2^53 - 1.
 *
 * A bundle does not name its trust domain, so the caller names it when reading, from the configuration it fetched the
 * bundle by; a bundle map names the trust domain of every bundle.
 *
 * The object holds no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto that decodes keys and certificates under its policy.
 * @property limits the limits of reading.
 * @since 1.0.0
 */
public class TrustBundles(public val crypto: Crypto, public val limits: SpiffeLimits = SpiffeLimits.Default) {
    private val keys = JsonWebKeys(crypto = crypto, limits = joseLimitsOf(limits))
    private val reader = BundleReader(keys = keys, limits = limits)
    private val writer = BundleWriter(keys)

    /**
     * Reads the bundle of [trustDomain].
     *
     * @param trustDomain the trust domain the bundle was fetched for.
     * @param text the JSON text, possibly from an attacker.
     * @return the bundle, or why it was refused.
     * @since 1.0.0
     */
    public fun decode(trustDomain: TrustDomain, text: String): Outcome<TrustBundle, BundleFailure> =
        reading { reader.bundle(trustDomain = trustDomain, text = text) }

    /**
     * Writes [bundle] as a SPIFFE bundle: `spiffe_sequence` and `spiffe_refresh_hint` if set, then `keys` with one
     * JWK per X.509 authority, with its certificate in `x5c` and without `kid`, and one per JWT authority, with `kid`.
     *
     * @param bundle the bundle.
     * @return the JSON text.
     * @throws IllegalArgumentException if JOSE has no key type for a key of the bundle, such as ML-DSA.
     * @since 1.0.0
     */
    public fun encode(bundle: TrustBundle): String = writer.bundle(bundle).encode()

    /**
     * Reads a SPIFFE bundle map: `trust_domains`, an object of bundles named by their trust domain. A duplicate trust
     * domain is refused, as section 5.1.1 demands. The refresh hints of the bundles of a map are read but, by the
     * specification, must not steer the refresh of the map.
     *
     * @param text the JSON text, possibly from an attacker.
     * @return the bundles, or why the map was refused.
     * @since 1.0.0
     */
    public fun decodeMap(text: String): Outcome<BundleSet, BundleFailure> = reading { reader.map(text) }

    /**
     * Writes [bundles] as a SPIFFE bundle map.
     *
     * @param bundles the bundles.
     * @return the JSON text.
     * @throws IllegalArgumentException if JOSE has no key type for a key of a bundle, such as ML-DSA.
     * @since 1.0.0
     */
    public fun encodeMap(bundles: BundleSet): String = writer.map(bundles).encode()

    /**
     * Shows the limits.
     *
     * @return the codec as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TrustBundles($limits)"

    private companion object {
        fun joseLimitsOf(limits: SpiffeLimits): JoseLimits = JoseLimits(
            maximumBytes = limits.maximumBytes,
            maximumMembers = maxOf(a = JoseLimits.DEFAULT_MAXIMUM_MEMBERS, b = limits.maximumTrustDomains),
            maximumStringLength = limits.maximumBytes,
            maximumKeys = limits.maximumAuthorities,
        )
    }
}
