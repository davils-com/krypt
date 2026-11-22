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

package com.davils.krypt.tls

import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm

/**
 * A group of the key exchange that krypt allows, in the order of preference.
 *
 * A group is offered only if the crypto policy of the environment permits its [algorithm] for protection and the JSSE
 * provider offers it. The hybrid group [X25519MlKem768] comes first: its secret stays safe while either of its
 * components holds, so the policy decides it by ML-KEM-768, the component that resists a quantum computer.
 *
 * @property groupName the name of the group in JSSE and in the IANA registry.
 * @property algorithm the algorithm the crypto policy decides the group by.
 * @property isPostQuantum whether the group resists a quantum computer.
 * @since 1.0.0
 */
public enum class NamedGroup(
    public val groupName: String,
    public val algorithm: Algorithm,
    public val isPostQuantum: Boolean = false,
) {
    /**
     * X25519MLKEM768: X25519 combined with ML-KEM-768, of the hybrid key exchange of TLS 1.3 by
     * RFC 10024.
     *
     * @since 1.0.0
     */
    X25519MlKem768("X25519MLKEM768", KemAlgorithm.MlKem768, isPostQuantum = true),

    /**
     * x25519.
     *
     * @since 1.0.0
     */
    X25519("x25519", KeyAgreementAlgorithm.X25519),

    /**
     * secp256r1, the curve P-256.
     *
     * @since 1.0.0
     */
    Secp256r1("secp256r1", KeyAgreementAlgorithm.EcdhP256),

    /**
     * secp384r1, the curve P-384.
     *
     * @since 1.0.0
     */
    Secp384r1("secp384r1", KeyAgreementAlgorithm.EcdhP384),

    /**
     * secp521r1, the curve P-521.
     *
     * @since 1.0.0
     */
    Secp521r1("secp521r1", KeyAgreementAlgorithm.EcdhP521),

    /**
     * x448.
     *
     * @since 1.0.0
     */
    X448("x448", KeyAgreementAlgorithm.X448),
}
