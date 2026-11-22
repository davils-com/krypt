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

package com.davils.krypt.spiffe.fixture

import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate

internal const val X509_USE: String = """"use":"x509-svid""""
internal const val JWT_USE: String = """"use":"jwt-svid""""
private const val COMMA: String = ","

internal val jsonWebKeys: JsonWebKeys = JsonWebKeys(crypto)

internal fun quoted(text: String): String = "\"$text\""

internal fun member(name: String, value: String): String = quoted(name) + ":" + value

internal fun array(items: List<String>): String = "[" + items.joinToString(separator = COMMA) + "]"

internal fun chainOf(vararg certificates: Certificate): String {
    val items = certificates.map { certificate -> quoted(Base64.encode(certificate.encoded)) }
    return member(name = "x5c", value = array(items))
}

internal fun jwkOf(key: PublicKey, keyId: String? = null): String = jsonWebKeys.of(key = key, keyId = keyId).encode()

internal fun entry(jwk: String, vararg members: String): String {
    val inner = jwk.removePrefix("{").removeSuffix("}")
    return "{" + (members.toList() + inner).joinToString(separator = COMMA) + "}"
}

internal fun x509Entry(certificate: Certificate): String =
    entry(jwkOf(checkNotNull(certificate.publicKey)), X509_USE, chainOf(certificate))

internal fun bundleOf(entries: List<String>, extra: List<String> = emptyList()): String {
    val keys = member(name = "keys", value = array(entries))
    return "{" + (extra + keys).joinToString(separator = COMMA) + "}"
}

internal fun bundleOf(vararg entries: String, extra: List<String> = emptyList()): String =
    bundleOf(entries = entries.toList(), extra = extra)
