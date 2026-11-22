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

package com.davils.krypt.core.algorithm

/**
 * A cryptographic algorithm krypt knows by name, with the facts a [com.davils.krypt.core.policy.CryptoPolicy] decides
 * on.
 *
 * Whether an algorithm is available on the running platform is a separate question, which the capabilities of
 * `krypt-primitive` answer: Ed448 or ML-KEM, for example, exist only on the JVM, and an older browser lacks Ed25519.
 *
 * @since 1.0.0
 */
public sealed interface Algorithm {
    /**
     * The canonical name, such as `SHA-256` or `AES-256-GCM`, which stays stable across versions.
     *
     * @since 1.0.0
     */
    public val algorithmName: String

    /**
     * The security strength in bits against a classical attacker, as NIST SP 800-57 counts it.
     *
     * @since 1.0.0
     */
    public val securityBits: Int

    /**
     * Tells whether the algorithm is broken or weak and exists only to read old data.
     *
     * @since 1.0.0
     */
    public val isLegacy: Boolean

    /**
     * Tells whether FIPS 140-3 approves the algorithm for new protection.
     *
     * @since 1.0.0
     */
    public val isFipsApproved: Boolean

    /**
     * Tells whether the algorithm resists an attacker with a cryptographically relevant quantum computer.
     *
     * @since 1.0.0
     */
    public val isPostQuantum: Boolean
}
