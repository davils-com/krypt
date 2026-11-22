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

package com.davils.krypt.jose.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedSet
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwk.Jwk
import com.davils.krypt.jose.jwk.JwkCurve
import com.davils.krypt.jose.jwk.JwkType
import com.davils.krypt.jose.jwk.KeyOperation
import com.davils.krypt.jose.jwk.KeyUse
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString

internal class JwkReader(private val certificates: Certificates, private val limits: JoseLimits) {
    fun read(json: JsonValue.Object): Jwk {
        val type = JwkType.of(json.requiredText(JwkNames.TYPE)) ?: refuse(JoseFailure.UnsupportedAlgorithm)
        refuseUnless(JwkNames.OTHER_PRIMES !in json, JoseFailure.UnsupportedAlgorithm)
        val curve = curveOf(type, json)
        val publicNames = PUBLIC_NAMES.getValue(type)
        val privateNames = PRIVATE_NAMES.getValue(type)
        val allowed = publicNames + privateNames + listOfNotNull(JwkNames.CURVE.takeIf { curve != null })
        require(JwkNames.KEY_PARAMETERS.all { name -> name !in json || name in allowed })
        val parameters = publicNames.map { name -> name to requireNotNull(json.bytes(name)) }
        val present = privateNames.filter { name -> name in json }
        require(present.isEmpty() || present.size == privateNames.size)
        require(type != JwkType.Oct || present.isNotEmpty())
        val secrets = present.map { name -> name to invariant(json.bytes(name)) }
        checkSizes(type = type, curve = curve, values = parameters + secrets)
        val use = json.text(JwkNames.USE)?.let { name -> KeyUse.of(name) ?: refuse(JoseFailure.UnsupportedAlgorithm) }
        val operations = operationsOf(json, use)
        JwkNames.TEXTS.forEach { name -> json.text(name) }
        require(JwkNames.CHAIN !in json || type != JwkType.Oct)
        val chain = chainOf(json)
        val jwk = Jwk(
            type = type,
            curve = curve,
            use = use,
            operations = operations,
            algorithm = json.text(JwkNames.ALGORITHM),
            keyId = json.text(JwkNames.KEY_ID),
            certificates = chain,
            parameters = parameters,
            secrets = secrets.map { (name, value) -> name to SecretBytes.copyOf(value) },
            extra = json.without(JwkNames.KNOWN),
        )
        val leaf = chain.firstOrNull()
        refuseUnless(leaf == null || leaf.subjectPublicKeyInfo == KeyDer.spki(jwk), JoseFailure.InvalidKey)
        return jwk
    }

    private fun curveOf(type: JwkType, json: JsonValue.Object): JwkCurve? {
        val name = json.text(JwkNames.CURVE)
        val isCurved = type == JwkType.Ec || type == JwkType.Okp
        require(isCurved == (name != null))
        val curve = name?.let { found -> JwkCurve.of(found) ?: refuse(JoseFailure.UnsupportedAlgorithm) }
        require(curve == null || curve.type == type)
        return curve
    }

    private fun checkSizes(type: JwkType, curve: JwkCurve?, values: List<Pair<String, ByteString>>) {
        values.forEach { (name, value) ->
            require(value.size > 0)
            require(type != JwkType.Rsa || value[0] != ZERO)
            if (curve != null) require(value.size == sizeOf(curve = curve, name = name))
        }
    }

    private fun sizeOf(curve: JwkCurve, name: String): Int = when (name == JwkNames.D) {
        true -> curve.privateBytes
        false -> curve.publicBytes
    }

    private fun operationsOf(json: JsonValue.Object, use: KeyUse?): List<KeyOperation> {
        val names = json.strings(JwkNames.OPERATIONS).orEmpty()
        require(OrderedSet(names).size == names.size)
        val operations = names.map { name -> KeyOperation.of(name) ?: refuse(JoseFailure.UnsupportedAlgorithm) }
        require(use == null || operations.all { operation -> operation.use == use })
        return operations
    }

    private fun chainOf(json: JsonValue.Object): List<Certificate> {
        val encoded = json.strings(JwkNames.CHAIN) ?: return emptyList()
        require(encoded.isNotEmpty())
        refuseUnless(encoded.size <= limits.maximumCertificates, JoseFailure.LimitExceeded)
        return encoded.map { text ->
            val der = requireNotNull(Base64Url.decodeStandard(text))
            requireNotNull(certificates.decode(der).getOrNull())
        }
    }

    private companion object {
        const val ZERO: Byte = 0

        val PUBLIC_NAMES: Map<JwkType, List<String>> = mapOf(
            JwkType.Ec to listOf(JwkNames.X, JwkNames.Y),
            JwkType.Okp to listOf(JwkNames.X),
            JwkType.Rsa to listOf(JwkNames.N, JwkNames.E),
            JwkType.Oct to emptyList(),
        )

        val PRIVATE_NAMES: Map<JwkType, List<String>> = mapOf(
            JwkType.Ec to listOf(JwkNames.D),
            JwkType.Okp to listOf(JwkNames.D),
            JwkType.Rsa to JwkNames.RSA_PRIVATE,
            JwkType.Oct to listOf(JwkNames.K),
        )
    }
}
