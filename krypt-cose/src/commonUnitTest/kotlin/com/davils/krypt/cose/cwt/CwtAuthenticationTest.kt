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
import com.davils.krypt.primitive.key.KeyPair
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.hours

private const val ISSUER: String = "coap://as.example.com"

private val cwt: Cwt = Cwt(cose)

private val genuine: CwtClaims = CwtClaims.of(issuer = ISSUER, subject = "alice", expiration = NOW + 1.hours)

private val forged: CwtClaims = CwtClaims.of(issuer = ISSUER, subject = "mallory", expiration = NOW + 1.hours)

private fun nested(configure: CwtValidationBuilder.() -> Unit = {}): CwtValidation = cwtValidation {
    algorithms(CoseAlgorithm.Esp256, CoseAlgorithm.EcdhEsHkdf256, CoseAlgorithm.A256Kw, CoseAlgorithm.A256Gcm)
    algorithms(CoseAlgorithm.Direct, CoseAlgorithm.Hmac256, CoseAlgorithm.EcdhEsA256Kw)
    issuer = ISSUER
    configure()
}

private suspend fun encrypted(payload: ByteString, vararg recipients: CoseRecipientSpec): ByteString =
    cose.encrypt(plaintext = payload, algorithm = CoseAlgorithm.A256Gcm, recipients = recipients.toList()).encode()

private suspend fun maced(payload: ByteString, recipient: CoseRecipientSpec): ByteString =
    cose.mac(payload = payload, algorithm = CoseAlgorithm.Hmac256, recipients = listOf(recipient)).encode()

private suspend fun pair(): KeyPair = crypto.keys.generate(KeyType.P256)

private fun agreement(recipient: KeyPair, algorithm: CoseAlgorithm = CoseAlgorithm.EcdhEsHkdf256): CoseRecipientSpec =
    CoseRecipientSpec(key = CoseKey.of(recipient.publicKey), algorithm = algorithm)

private fun keysOf(authority: KeyPair, recipient: KeyPair): List<CoseKey> =
    listOf(CoseKey.of(authority.publicKey), CoseKey.of(recipient.privateKey))

class CwtAuthenticationTest : FunSpec({
    test("a signed CWT encrypted to an ECDH-ES recipient is authenticated by its signature") {
        val authority = pair()
        val recipient = pair()
        val signer = CoseSigner(key = CoseKey.of(authority.privateKey), algorithm = CoseAlgorithm.Esp256)
        val outer = encrypted(cwt.sign(genuine, signer), agreement(recipient))
        val keys = keysOf(authority, recipient)
        cwt.validate(encoded = outer, keys = keys, validation = nested()).value() shouldBe genuine
    }

    test("a CWT protected only by an ECDH-ES recipient is refused unless authentication is turned off") {
        val recipient = pair()
        val keys = keysOf(authority = pair(), recipient = recipient)
        val payload = Cbor.encode(forged.claims)
        val unauthenticated = nested { isAuthenticationRequired = false }
        listOf(
            encrypted(payload, agreement(recipient)),
            maced(payload, agreement(recipient)),
            encrypted(payload, agreement(recipient, CoseAlgorithm.EcdhEsA256Kw)),
        ).forEach { encoded ->
            cwt.validate(encoded = encoded, keys = keys, validation = nested()).failure() shouldBe
                CwtFailure.Unauthenticated
            cwt.validate(encoded = encoded, keys = keys, validation = unauthenticated).value() shouldBe forged
        }
        val unopened = encrypted(payload, agreement(recipient))
        cwt.validate(encoded = unopened, keys = emptyList(), validation = nested()).failure() shouldBe
            CwtFailure.DecryptionFailed
    }

    test("MACs and encryption under a pre-shared key authenticate the issuer") {
        val recipient = pair()
        val keys = keysOf(authority = pair(), recipient = recipient)
        val secret = CoseKey.of(crypto.keys.generateSecret())
        val payload = Cbor.encode(genuine.claims)
        val direct = CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.Direct)
        val wrapping = CoseRecipientSpec(key = secret, algorithm = CoseAlgorithm.A256Kw)
        listOf(
            cwt.mac(claims = genuine, key = secret, algorithm = CoseAlgorithm.Hmac256),
            cwt.encrypt(claims = genuine, key = secret, algorithm = CoseAlgorithm.A256Gcm),
            maced(payload, direct),
            encrypted(payload, direct),
            encrypted(payload, wrapping),
            encrypted(payload, wrapping, agreement(recipient, CoseAlgorithm.EcdhEsA256Kw)),
        ).forEach { encoded ->
            val outcome = cwt.validate(encoded = encoded, keys = listOf(secret) + keys, validation = nested())
            outcome.value() shouldBe genuine
        }
        val preSharedOnly = cwtValidation {
            algorithms(CoseAlgorithm.A256Kw, CoseAlgorithm.A256Gcm)
            issuer = ISSUER
        }
        val wrapped = encrypted(payload, wrapping)
        cwt.validate(encoded = wrapped, keys = listOf(secret), validation = preSharedOnly).value() shouldBe genuine
        cwt.validate(encoded = wrapped, keys = keys, validation = preSharedOnly).failure() shouldBe
            CwtFailure.DecryptionFailed
    }

    test("the requirement of authentication is part of the validation") {
        nested().isAuthenticationRequired shouldBe true
        val relaxed = nested { isAuthenticationRequired = false }
        relaxed.isAuthenticationRequired shouldBe false
        (relaxed == nested()) shouldBe false
        relaxed.toString() shouldContain "authenticationRequired=false"
    }
})
