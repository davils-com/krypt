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

package com.davils.krypt.cose.cwt

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseRecipientSpec
import com.davils.krypt.cose.CoseSigner
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.fixture.NOW
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Duration.Companion.hours

private const val ISSUER: String = "coap://as.example.com"

class AuditCwtTest : FunSpec({
    test("a CWT protected only by an ECDH-ES recipient is not accepted as issued by the issuer") {
        val authority = crypto.keys.generate(KeyType.P256)
        val recipient = crypto.keys.generate(KeyType.P256)
        val cwt = Cwt(cose)
        val validation = cwtValidation {
            algorithms(CoseAlgorithm.Esp256, CoseAlgorithm.EcdhEsHkdf256, CoseAlgorithm.A256Gcm)
            issuer = ISSUER
        }
        val keys = listOf(CoseKey.of(authority.publicKey), CoseKey.of(recipient.privateKey))
        val recipientSpec = CoseRecipientSpec(key = CoseKey.of(recipient.publicKey), algorithm = CoseAlgorithm.EcdhEsHkdf256)
        val genuine = CwtClaims.of(issuer = ISSUER, subject = "alice", expiration = NOW + 1.hours)
        val signed = cwt.sign(genuine, CoseSigner(key = CoseKey.of(authority.privateKey), algorithm = CoseAlgorithm.Esp256))
        val nested = cose.encrypt(
            plaintext = signed,
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(recipientSpec),
        ).encode()
        cwt.validate(encoded = nested, keys = keys, validation = validation).value() shouldBe genuine
        val forged = CwtClaims.of(issuer = ISSUER, subject = "mallory", expiration = NOW + 1.hours)
        val attacker = cose.encrypt(
            plaintext = Cbor.encode(forged.claims),
            algorithm = CoseAlgorithm.A256Gcm,
            recipients = listOf(recipientSpec),
        ).encode()
        cwt.validate(encoded = attacker, keys = keys, validation = validation).failure() shouldNotBe null
    }
})
