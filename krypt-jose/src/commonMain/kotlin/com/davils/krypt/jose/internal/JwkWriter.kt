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

package com.davils.krypt.jose.internal

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwk.Jwk

internal object JwkWriter {
    fun objectOf(jwk: Jwk): JsonValue.Object {
        val members = ArrayList<Pair<String, JsonValue>>()
        members += JwkNames.TYPE to text(jwk.type.typeName)
        jwk.curve?.let { curve -> members += JwkNames.CURVE to text(curve.curveName) }
        jwk.parameters.forEach { (name, value) -> members += name to encoded(value) }
        jwk.secrets.forEach { (name, secret) ->
            members += name to secretText(secret)
        }
        jwk.use?.let { use -> members += JwkNames.USE to text(use.useName) }
        if (jwk.operations.isNotEmpty()) {
            val operations = jwk.operations.map { operation -> text(operation.operationName) }
            members += JwkNames.OPERATIONS to JsonValue.Array(operations)
        }
        jwk.algorithm?.let { algorithm -> members += JwkNames.ALGORITHM to text(algorithm) }
        jwk.keyId?.let { keyId -> members += JwkNames.KEY_ID to text(keyId) }
        if (jwk.certificates.isNotEmpty()) {
            val chain = jwk.certificates.map { certificate -> text(Base64Url.encodeStandard(certificate.encoded)) }
            members += JwkNames.CHAIN to JsonValue.Array(chain)
        }
        members += jwk.extra.members
        return JsonValue.Object(members)
    }

    fun thumbprintInput(jwk: Jwk): ByteArray {
        val required = ArrayList<Pair<String, JsonValue>>()
        required += JwkNames.TYPE to text(jwk.type.typeName)
        jwk.curve?.let { curve -> required += JwkNames.CURVE to text(curve.curveName) }
        jwk.parameters.forEach { (name, value) -> required += name to encoded(value) }
        jwk.secret(JwkNames.K)?.let { key -> required += JwkNames.K to secretText(key) }
        val sorted = JsonValue.Object(required.sortedBy { member -> member.first })
        return JsonWriter.bytes(sorted)
    }

    private fun secretText(secret: SecretBytes): JsonValue.Text =
        secret.reveal { bytes -> text(Base64Url.encode(bytes)) }
}
