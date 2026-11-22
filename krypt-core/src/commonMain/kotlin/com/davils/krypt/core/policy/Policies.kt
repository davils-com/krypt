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

package com.davils.krypt.core.policy

/**
 * Builds a validated policy that starts from [profile] and changes what [configure] sets.
 *
 * @param profile the profile every setting starts from; [CryptoProfile.Modern] by default.
 * @param configure narrows or widens the profile, such as `forbid(SignatureAlgorithm.RsaPkcs1Sha256)`.
 * @return the policy.
 * @throws com.davils.kore.core.validation.report.ValidationException if a bound lies outside its hard ceiling or the
 *   bounds are not ordered.
 * @since 1.0.0
 */
public fun cryptoPolicy(
    profile: CryptoProfile = CryptoProfile.Modern,
    configure: CryptoPolicyBuilder.() -> Unit,
): CryptoPolicy {
    val builder = CryptoPolicyBuilder(profile)
    builder.configure()
    return builder.build()
}
