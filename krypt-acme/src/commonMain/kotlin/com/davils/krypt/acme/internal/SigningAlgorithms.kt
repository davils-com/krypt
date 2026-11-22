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

package com.davils.krypt.acme.internal

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.primitive.key.PublicKey

internal object SigningAlgorithms {
    private val RSA: Set<KeyFamily> = setOf(KeyFamily.Rsa)
    private val EC: Set<KeyFamily> = setOf(KeyFamily.Ec)
    private val EDWARDS: Set<KeyFamily> = setOf(KeyFamily.Ed25519, KeyFamily.Ed448)

    private val FAMILIES: Map<JwsAlgorithm, Set<KeyFamily>> = mapOf(
        JwsAlgorithm.RS256 to RSA,
        JwsAlgorithm.RS384 to RSA,
        JwsAlgorithm.RS512 to RSA,
        JwsAlgorithm.PS256 to RSA,
        JwsAlgorithm.PS384 to RSA,
        JwsAlgorithm.PS512 to RSA,
        JwsAlgorithm.ES256 to EC,
        JwsAlgorithm.ES384 to EC,
        JwsAlgorithm.ES512 to EC,
        JwsAlgorithm.EdDSA to EDWARDS,
        JwsAlgorithm.Ed25519 to setOf(KeyFamily.Ed25519),
        JwsAlgorithm.Ed448 to setOf(KeyFamily.Ed448),
    )

    private val CURVES: Map<JwsAlgorithm, EllipticCurve> = mapOf(
        JwsAlgorithm.ES256 to EllipticCurve.P256,
        JwsAlgorithm.ES384 to EllipticCurve.P384,
        JwsAlgorithm.ES512 to EllipticCurve.P521,
    )

    private val DEFAULTS: Map<KeyFamily, JwsAlgorithm> = mapOf(
        KeyFamily.Rsa to JwsAlgorithm.RS256,
        KeyFamily.Ed25519 to JwsAlgorithm.EdDSA,
        KeyFamily.Ed448 to JwsAlgorithm.EdDSA,
    )

    fun fits(algorithm: JwsAlgorithm, key: PublicKey): Boolean {
        val isFamily = key.family in FAMILIES[algorithm].orEmpty()
        return isFamily && CURVES[algorithm] == key.curve
    }

    fun defaultFor(family: KeyFamily, curve: EllipticCurve?): JwsAlgorithm? {
        val ecdsa = CURVES.entries.firstOrNull { (_, found) -> found == curve }?.key
        return DEFAULTS[family] ?: ecdsa?.takeIf { family == KeyFamily.Ec }
    }
}
