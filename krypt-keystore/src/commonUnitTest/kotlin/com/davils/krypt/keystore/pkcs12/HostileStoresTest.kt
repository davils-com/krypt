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

package com.davils.krypt.keystore.pkcs12

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.keystore.KeystoreFailure
import com.davils.krypt.keystore.fixture.ITERATIONS
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.der
import com.davils.krypt.keystore.fixture.identity
import com.davils.krypt.keystore.fixture.password
import com.davils.krypt.keystore.internal.BagAttributes
import com.davils.krypt.keystore.internal.Pkcs12Kdf
import com.davils.krypt.keystore.internal.Pkcs12Oids
import com.davils.krypt.keystore.internal.Pkcs12Writer
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SALT_BYTES: Int = 16
private const val SHORT: Int = 8
private const val KEY_BYTES: Int = 32
private const val VERSION: Long = 3L
private const val LONG_NAME: String = "a friendly name longer than the key id"
private val GARBAGE: ByteString = ByteString(1, 2, 3)
private val SALT: ByteString = ByteString(ByteArray(SALT_BYTES) { index -> index.toByte() })
private val ENVELOPED: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.3")
private val SHA1: ObjectIdentifier = ObjectIdentifier.of("1.3.14.3.2.26")
private val SHA256: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.1")
private val HMAC_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.10")
private val OTHER: ObjectIdentifier = ObjectIdentifier.of("1.2.3.4")

private suspend fun pbmac1(authenticated: ByteString): ByteString {
    val derived = crypto.derivations.pbkdf2(
        password = password(),
        salt = SALT,
        iterations = ITERATIONS,
        length = KEY_BYTES,
    )
    val key = derived.use { bytes -> SecretKey.of(bytes) }
    val tag = crypto.macs.mac(key, authenticated)
    return Pkcs12Writer.pfx(authenticated = authenticated, salt = SALT, iterations = ITERATIONS, tag = tag)
}

private suspend fun classic(authenticated: ByteString, iterations: Int? = null): ByteString {
    val derived = Pkcs12Kdf.macKey(
        crypto = crypto,
        digest = DigestAlgorithm.Sha256,
        password = password(),
        salt = SALT,
        iterations = iterations ?: 1,
    )
    val key = derived.use { bytes -> SecretKey.of(bytes) }
    val tag = crypto.macs.mac(key, authenticated, MacAlgorithm.HmacSha256)
    return pfx(authenticated) {
        sequence {
            sequence {
                objectIdentifier(SHA256)
                nullValue()
            }
            octetString(tag)
        }
        octetString(SALT)
        iterations?.let { count -> integer(count.toLong()) }
    }
}

private fun pfx(authenticated: ByteString, mac: (DerWriter.() -> Unit)?): ByteString = der {
    sequence {
        integer(VERSION)
        raw(Pkcs12Writer.plain(authenticated))
        mac?.let { body -> sequence(body) }
    }
}

private fun pbmac1Algorithm(
    salt: ByteString = SALT,
    keyBytes: Int = KEY_BYTES,
    prf: ObjectIdentifier? = Pkcs12Oids.HMAC_SHA256,
    hmac: ObjectIdentifier = Pkcs12Oids.HMAC_SHA256,
): DerWriter.() -> Unit = {
    sequence {
        sequence {
            objectIdentifier(Pkcs12Oids.PBMAC1)
            sequence {
                sequence {
                    objectIdentifier(Pkcs12Oids.PBKDF2)
                    sequence {
                        octetString(salt)
                        integer(ITERATIONS.toLong())
                        integer(keyBytes.toLong())
                        prf?.let { id -> sequence { objectIdentifier(id) } }
                    }
                }
                sequence { objectIdentifier(hmac) }
            }
        }
        octetString(ByteString(ByteArray(KEY_BYTES)))
    }
    octetString(SALT)
}

private fun bags(bags: List<ByteString>): ByteString {
    val contents = Pkcs12Writer.plain(Pkcs12Writer.safeContents(bags))
    return Pkcs12Writer.authenticatedSafe(listOf(contents))
}

private fun bags(bag: ByteString): ByteString = bags(listOf(bag))

private suspend fun decoded(file: ByteString): KeystoreFailure? {
    val outcome = Pkcs12(crypto).decode(file, password())
    return outcome.failureOrNull()
}

private suspend fun store(file: ByteString): Pkcs12Store? {
    val outcome = Pkcs12(crypto).decode(file, password())
    return outcome.getOrNull()
}

class HostileStoresTest : FunSpec({
    test("files without a MAC or of a foreign shape are refused") {
        val empty = Pkcs12Writer.authenticatedSafe(emptyList())
        decoded(pfx(empty, mac = null)) shouldBe KeystoreFailure.Unsupported
        decoded(GARBAGE) shouldBe KeystoreFailure.Malformed
        val foreign = Pkcs12Writer.authenticatedSafe(
            listOf(
                der {
                    sequence {
                        objectIdentifier(ENVELOPED)
                        explicit(0) { sequence { } }
                    }
                },
            ),
        )
        decoded(pbmac1(foreign)) shouldBe KeystoreFailure.Unsupported
        decoded(pbmac1(der { nullValue() })) shouldBe KeystoreFailure.Malformed
        decoded(pbmac1(bags(der { nullValue() }))) shouldBe KeystoreFailure.Malformed
        val wrongInner = Pkcs12Writer.authenticatedSafe(listOf(Pkcs12Writer.plain(der { nullValue() })))
        decoded(pbmac1(wrongInner)) shouldBe KeystoreFailure.Malformed
        val badCipher = Pkcs12Writer.authenticatedSafe(
            listOf(Pkcs12Writer.encrypted(algorithm = der { sequence { objectIdentifier(OTHER) } }, ciphertext = SALT)),
        )
        decoded(pbmac1(badCipher)) shouldBe KeystoreFailure.Unsupported
        val unknownDigest = pfx(empty) {
            sequence {
                sequence { objectIdentifier(OTHER) }
                octetString(SALT)
            }
            octetString(SALT)
        }
        decoded(unknownDigest) shouldBe KeystoreFailure.Unsupported
        val noAlgorithm = pfx(empty) {
            sequence {
                nullValue()
                octetString(SALT)
            }
            octetString(SALT)
        }
        decoded(noAlgorithm) shouldBe KeystoreFailure.Malformed
        val brokenAlgorithm = pfx(empty) {
            sequence {
                sequence { integer(1L) }
                octetString(SALT)
            }
            octetString(SALT)
        }
        decoded(brokenAlgorithm) shouldBe KeystoreFailure.Malformed
        val notData = der {
            sequence {
                integer(VERSION)
                sequence {
                    objectIdentifier(OTHER)
                    explicit(0) { octetString(empty) }
                }
            }
        }
        decoded(notData) shouldBe KeystoreFailure.Malformed
    }

    test("every MAC parameter is checked") {
        val empty = Pkcs12Writer.authenticatedSafe(emptyList())
        decoded(pfx(empty, pbmac1Algorithm(salt = ByteString(ByteArray(SHORT))))) shouldBe KeystoreFailure.Unsupported
        decoded(pfx(empty, pbmac1Algorithm(keyBytes = SHORT))) shouldBe KeystoreFailure.Refused
        decoded(pfx(empty, pbmac1Algorithm(prf = null))) shouldBe KeystoreFailure.Unsupported
        decoded(pfx(empty, pbmac1Algorithm(prf = HMAC_SHA384))) shouldBe KeystoreFailure.Unsupported
        decoded(pfx(empty, pbmac1Algorithm(hmac = OTHER))) shouldBe KeystoreFailure.Unsupported
        decoded(pfx(empty, pbmac1Algorithm(prf = OTHER))) shouldBe KeystoreFailure.Unsupported
        decoded(
            pfx(empty) {
                sequence {
                    sequence { objectIdentifier(SHA1) }
                    octetString(SALT)
                }
                octetString(SALT)
            },
        ) shouldBe KeystoreFailure.Unsupported
        store(classic(empty)) shouldBe Pkcs12Store()
        store(classic(empty, iterations = 2)) shouldBe Pkcs12Store()
        decoded(pbmac1(empty)) shouldBe null
    }

    test("bags are read, skipped or refused") {
        val (server, _) = identity()
        val plainKey = crypto.keys.encodePrivate(server.privateKey).use { encoded ->
            encoded.reveal { bytes -> ByteString(bytes) }
        }
        val named = BagAttributes(friendlyName = LONG_NAME, localKeyId = SALT)
        val keyBag = Pkcs12Writer.bag(Pkcs12Oids.KEY_BAG, plainKey, named)
        val certificateBags = server.chain.map { certificate ->
            Pkcs12Writer.certificateBag(certificate.encoded, BagAttributes(localKeyId = SALT))
        }
        val otherCertificate = Pkcs12Writer.bag(
            Pkcs12Oids.CERTIFICATE_BAG,
            der {
                sequence {
                    objectIdentifier(OTHER)
                    explicit(0) { octetString(SALT) }
                }
            },
            BagAttributes(),
        )
        val unknownBag = Pkcs12Writer.bag(OTHER, der { nullValue() }, BagAttributes())
        val strangeAttribute = der {
            sequence {
                objectIdentifier(OTHER)
                explicit(0) { nullValue() }
                setOf {
                    sequence {
                        objectIdentifier(OTHER)
                        setOf { nullValue() }
                    }
                }
            }
        }
        val file = pbmac1(bags(listOf(keyBag, otherCertificate, unknownBag, strangeAttribute) + certificateBags))
        val read = checkNotNull(store(file))
        val entry = read.keys.single()
        entry.alias shouldBe LONG_NAME
        val unnamed = Pkcs12Writer.bag(Pkcs12Oids.KEY_BAG, plainKey, BagAttributes(friendlyName = "plain"))
        val byPair = checkNotNull(store(pbmac1(bags(listOf(unnamed) + certificateBags))))
        byPair.keys.single().identity shouldBe server
        entry.identity shouldBe server
        read.certificates shouldBe emptyList()
        decoded(pbmac1(bags(keyBag))) shouldBe KeystoreFailure.Malformed
        val emptyKey = Pkcs12Writer.bag(Pkcs12Oids.KEY_BAG, der { sequence { } }, named)
        decoded(pbmac1(bags(emptyKey))) shouldBe KeystoreFailure.Malformed
        val brokenCertificate = Pkcs12Writer.certificateBag(SALT, BagAttributes())
        decoded(pbmac1(bags(brokenCertificate))) shouldBe KeystoreFailure.Malformed
        val twoNames = der {
            sequence {
                objectIdentifier(OTHER)
                explicit(0) { nullValue() }
                setOf {
                    sequence {
                        objectIdentifier(Pkcs12Oids.FRIENDLY_NAME)
                        setOf {
                            element(Tag.BmpString, ByteString(0, 'a'.code.toByte()))
                            element(Tag.BmpString, ByteString(0, 'b'.code.toByte()))
                        }
                    }
                }
            }
        }
        decoded(pbmac1(bags(twoNames))) shouldBe KeystoreFailure.Malformed
    }
})
