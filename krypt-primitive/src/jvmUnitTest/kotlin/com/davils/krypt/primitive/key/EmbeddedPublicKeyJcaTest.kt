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

package com.davils.krypt.primitive.key

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.fixture.on
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val GARBAGE_BYTES: Int = 3

private val malformed: Outcome<PrivateKey, KeyFailure> = Outcome.Failure(KeyFailure.Malformed)

private fun bitsOf(key: PublicKey): ByteString {
    val bits = checkNotNull(
        Der.decodeOrNull(key.encoded) {
            readSequence {
                readElement(Tag.Sequence)
                readBitString()
            }
        },
    )
    val encoded = Der.encode { bitString(BitString(bits.bytes)) }
    return checkNotNull(Der.decodeOrNull(encoded) { readElement(Tag.BitString).content })
}

private fun partsOf(pkcs8: SecretBytes): Pair<DerElement, ByteString> = pkcs8.reveal { bytes ->
    checkNotNull(
        Der.decodeOrNull(ByteString(bytes)) {
            readSequence {
                readInteger()
                val algorithm = readElement(Tag.Sequence)
                val privateKey = readOctetString()
                readRemaining()
                algorithm to privateKey
            }
        },
    )
}

private fun pkcs8Of(algorithm: DerElement, privateKey: ByteString, publicKey: PublicKey): SecretBytes {
    val encoded = Der.encode {
        sequence {
            integer(1L)
            raw(algorithm.encoded)
            octetString(privateKey)
            element(tag = Tag.context(number = 1, isConstructed = false), content = bitsOf(publicKey))
        }
    }
    return SecretBytes.copyOf(encoded)
}

class EmbeddedPublicKeyJcaTest : FunSpec({
    val crypto = Crypto()

    context("an ML-DSA or ML-KEM key whose embedded public key belongs to another key is malformed") {
        withData(listOf(KeyType.MlDsa44, KeyType.MlKem768, KeyType.MlKem1024)) { type ->
            val own = crypto.keys.generate(type)
            val other = crypto.keys.generate(type)
            val (algorithm, privateKey) = partsOf(crypto.keys.encodePrivate(own.privateKey))
            val foreign = pkcs8Of(algorithm = algorithm, privateKey = privateKey, publicKey = other.publicKey)
            crypto.keys.decodePrivate(foreign) shouldBe malformed
            val paired = pkcs8Of(algorithm = algorithm, privateKey = privateKey, publicKey = own.publicKey)
            val decoded = crypto.keys.decodePrivate(paired)
            decoded.getOrNull()?.publicKey shouldBe own.publicKey
        }
    }

    test("an ML-KEM key the platform refuses is malformed, whatever public key it carries") {
        val own = crypto.keys.generate(KeyType.MlKem768)
        val (algorithm, _) = partsOf(crypto.keys.encodePrivate(own.privateKey))
        val garbage = ByteString(ByteArray(GARBAGE_BYTES))
        val encoding = pkcs8Of(algorithm = algorithm, privateKey = garbage, publicKey = own.publicKey)
        crypto.keys.decodePrivate(encoding) shouldBe malformed
    }

    test("a provider that lacks the algorithm of a key cannot check its public key, so the key carries none") {
        val sun = on("SUN")
        val ed25519 = crypto.keys.generate(KeyType.Ed25519)
        val (algorithm, privateKey) = partsOf(crypto.keys.encodePrivate(ed25519.privateKey))
        val encoding = pkcs8Of(algorithm = algorithm, privateKey = privateKey, publicKey = ed25519.publicKey)
        val unchecked = checkNotNull(sun.keys.decodePrivate(encoding).getOrNull())
        unchecked.publicKey.shouldBeNull()
        val x25519 = crypto.keys.generate(KeyType.X25519)
        val bare = sun.keys.decodePrivate(crypto.keys.encodePrivate(x25519.privateKey))
        bare.getOrNull()?.publicKey.shouldBeNull()
        shouldThrow<UnsupportedAlgorithmException> { sun.agreements.agree(x25519.privateKey, x25519.publicKey) }
    }
})
