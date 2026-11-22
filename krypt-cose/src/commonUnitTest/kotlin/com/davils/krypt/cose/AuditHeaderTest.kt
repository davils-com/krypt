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

package com.davils.krypt.cose

import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborTag
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val MAC0_TAG: ULong = 17UL
private const val TRUNCATED: Int = 8

class AuditHeaderTest : FunSpec({
    test("an unprotected alg cannot downgrade HMAC 256/256 to HMAC 256/64") {
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val payload = utf8("pay 10 EUR to alice")
        val unprotectedAlgorithm = CoseHeaders.of(CborMap.of(CborInteger.of(1) to CborInteger.of(CoseAlgorithm.Hmac256.id)))
        val genuine = cose.mac0(
            payload = payload,
            key = secret,
            algorithm = CoseAlgorithm.Hmac256,
            unprotectedHeaders = unprotectedAlgorithm,
        )
        val allowed = setOf(CoseAlgorithm.Hmac256, CoseAlgorithm.Hmac256Truncated64)
        cose.verify(message = genuine, keys = listOf(secret), algorithms = allowed).value()
        val downgraded = CborTag(
            number = MAC0_TAG,
            content = CborArray.of(
                CborBytes(ByteString()),
                CborMap.of(CborInteger.of(1) to CborInteger.of(CoseAlgorithm.Hmac256Truncated64.id)),
                CborBytes(payload),
                CborBytes(genuine.tag.substring(startIndex = 0, endIndex = TRUNCATED)),
            ),
        )
        val message = cose.decodeMac0(Cbor.encode(downgraded)).value()
        cose.verify(message = message, keys = listOf(secret), algorithms = allowed).failure() shouldNotBe null
    }
})
