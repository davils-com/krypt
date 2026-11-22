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

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.extension.DistributionPoint
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.extension.PolicyConstraints
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.certificates
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.internal.NameCodec.readGeneralNames
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val HOST: String = "example.com"
private const val LIMIT: Int = 2
private const val OVER: Int = 3
private const val UNUSED_BITS: Int = 8
private const val SERIAL_BYTES: Int = 22
private const val LONG_INTEGER: Int = 9
private const val NEGATIVE: Byte = -128

private suspend fun issue(block: ExtensionsBuilder.() -> Unit): Certificate {
    val pair = crypto.keys.generate(KeyType.P256)
    return certificates.issue(crypto.signatures.signer(pair.privateKey)) {
        publicKey = pair.publicKey
        notBefore = NOW
        notAfter = NOW
        extensions(block)
    }
}

private suspend fun refuses(id: ObjectIdentifier, value: ByteString) {
    shouldThrow<IllegalStateException> { issue { add(Extension(id, false, value)) } }
}

private fun names(block: DerWriter.() -> Unit): List<GeneralName>? = Der.decodeOrNull(
    der { sequence(block) },
) { readGeneralNames(LIMIT) }

private fun context(number: Int, isConstructed: Boolean = false): Tag =
    Tag.context(number = number, isConstructed = isConstructed)

class DecodingTest : FunSpec({
    test("general names of every kind are read, odd ones kept as they are") {
        val other = der {
            constructed(
                context(number = 0, isConstructed = true),
            ) {
                objectIdentifier(ObjectIdentifier.of("1.2.3"))
                explicit(number = 0) { utf8String("x") }
            }
        }
        val parsed = checkNotNull(
            names {
                raw(other)
                ia5String(HOST, context(number = 1))
            },
        )
        parsed.first().toString() shouldBe "other:${com.davils.krypt.core.encoding.Hex.encode(other)}"
        parsed.first() shouldBe checkNotNull(names { raw(other) }).single()
        parsed.first().hashCode() shouldBe other.hashCode()
        val x400 = der { constructed(context(number = 3, isConstructed = true)) { nullValue() } }
        parsed.first() shouldNotBe checkNotNull(names { raw(x400) }).single()
        val certificate = issue { subjectAlternativeNames(parsed) }
        certificate.extensions.subjectAlternativeNames shouldBe parsed
        names { element(context(number = 1), ByteString(-1)) } shouldBe null
        names { octetString(ByteString(ByteArray(OVER) { 1 }), context(number = 7)) } shouldBe null
        names { ia5String(HOST, context(number = 4)) } shouldBe null
        names {
            explicit(number = 4) {
                raw(distinguishedName { commonName("a") }.encoded)
                nullValue()
            }
        } shouldBe null
        names { element(context(number = 8), ByteString(NEGATIVE)) } shouldBe null
        names { utf8String(HOST) } shouldBe null
        names { repeat(OVER) { ia5String(HOST, context(number = 2)) } } shouldBe null
        names { } shouldBe null
        names {
            constructed(
                context(number = 3, isConstructed = true),
            ) { nullValue() }
            constructed(context(number = 5, true)) { nullValue() }
        }?.size shouldBe LIMIT
    }

    test("malformed values of known extensions are refused") {
        refuses(
            ExtensionIds.AuthorityKeyIdentifier,
            der { sequence { element(context(number = 2), ByteString(0, 1)) } },
        )
        refuses(
            ExtensionIds.SubjectAlternativeName,
            der { sequence { repeat(X509Limits.DEFAULT_MAXIMUM_NAMES + 1) { ia5String(HOST, context(number = 2)) } } },
        )
        refuses(ExtensionIds.NameConstraints, der { sequence { constructed(context(number = 0, true)) { } } })
        refuses(ExtensionIds.PolicyConstraints, der { sequence { element(context(number = 0), ByteString(-1)) } })
        refuses(
            ExtensionIds.PolicyConstraints,
            der { sequence { element(context(number = 1), ByteString(ByteArray(LONG_INTEGER) { 1 })) } },
        )
        refuses(
            ExtensionIds.CrlDistributionPoints,
            der { sequence { sequence { element(context(number = 1), ByteString(UNUSED_BITS.toByte())) } } },
        )
        refuses(
            ExtensionIds.CrlDistributionPoints,
            der { sequence { sequence { element(context(number = 1), ByteString(1)) } } },
        )
        refuses(
            ExtensionIds.CrlDistributionPoints,
            der { sequence { sequence { element(context(number = 1), ByteString()) } } },
        )
        refuses(
            ExtensionIds.CrlDistributionPoints,
            der { sequence { sequence { constructed(context(number = 2, true)) { } } } },
        )
        val many = der {
            sequence {
                constructed(context(number = 0, true)) {
                    repeat(X509Limits.DEFAULT_MAXIMUM_NAMES + 1) { sequence { ia5String(HOST, context(number = 2)) } }
                }
            }
        }
        refuses(ExtensionIds.NameConstraints, many)
        val issuers = der {
            sequence {
                sequence {
                    constructed(
                        context(number = 2, isConstructed = true),
                    ) { repeat(X509Limits.DEFAULT_MAXIMUM_NAMES + 1) { ia5String(HOST, context(number = 2)) } }
                }
            }
        }
        refuses(ExtensionIds.CrlDistributionPoints, issuers)
    }

    test("one-sided constraints and sparse distribution points are written and read") {
        val certificate = issue {
            nameConstraints(NameConstraints(permitted = listOf(GeneralName.Dns(HOST))))
            policyConstraints(PolicyConstraints(inhibitPolicyMapping = 0))
            crlDistributionPoints(
                listOf(DistributionPoint(names = emptyList(), crlIssuer = listOf(GeneralName.Dns(HOST)))),
            )
            add(Extension(ExtensionIds.BasicConstraints, true, der { sequence { boolean(true) } }))
        }
        certificate.extensions.nameConstraints?.excluded shouldBe emptyList()
        certificate.extensions.policyConstraints shouldBe PolicyConstraints(inhibitPolicyMapping = 0)
        certificate.extensions.crlDistributionPoints
            .single()
            .crlIssuer shouldBe listOf(GeneralName.Dns(HOST))
        certificate.isCa shouldBe true
        val excludedOnly = issue { nameConstraints(NameConstraints(excluded = listOf(GeneralName.Dns(HOST)))) }
        excludedOnly.extensions.nameConstraints?.permitted shouldBe emptyList()
        excludedOnly.isCa shouldBe false
        shouldThrow<IllegalArgumentException> { ExtensionsBuilder().certificatePolicies(emptyList()) }
    }

    test("certificate structures that break the rules are refused") {
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = crypto.signatures.signer(pair.privateKey)
        val template = issue { }

        fun tbs(version: Long?, serial: ByteString, extensions: List<Extension>?): ByteString = der {
            sequence {
                raw(
                    der {
                        sequence {
                            version?.let { found -> explicit(number = 0) { integer(found) } }
                            integer(
                                com.davils.krypt.asn1.DerInteger
                                    .ofMagnitude(serial),
                            )
                            raw(AlgorithmIdentifiers.encode(signer.algorithm))
                            raw(template.issuer.encoded)
                            sequence {
                                time(NOW)
                                time(NOW)
                            }
                            raw(template.subject.encoded)
                            raw(pair.publicKey.encoded)
                            extensions?.let { found ->
                                explicit(number = 3) {
                                    sequence {
                                        found.forEach { extension ->
                                            sequence {
                                                objectIdentifier(extension.id)
                                                octetString(extension.value)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                )
                raw(AlgorithmIdentifiers.encode(signer.algorithm))
                bitString(BitString(ByteString(1)))
            }
        }
        val one = ByteString(1)
        certificates.decode(tbs(null, one, null)).getOrNull()?.version shouldBe 1
        val outcome236 = certificates.decode(
            tbs(null, one, listOf(Extension(ExtensionIds.OcspNoCheck, false, der { nullValue() }))),
        )
        outcome236.failureOrNull() shouldBe
            X509Failure.Malformed
        val outcome241 = certificates.decode(
            tbs(2L, ByteString(ByteArray(SERIAL_BYTES) { 1 }), null),
        )
        outcome241.failureOrNull() shouldBe X509Failure.Malformed
        certificates.decode(tbs(2L, one, emptyList())).failureOrNull() shouldBe X509Failure.Malformed
        val tooMany = List(OVER) { index -> Extension(ObjectIdentifier.of("1.2.3.$index"), false, der { nullValue() }) }
        val narrow = Certificates(crypto, X509Limits(maximumExtensions = LIMIT))
        narrow.decode(tbs(2L, one, tooMany)).failureOrNull() shouldBe X509Failure.Malformed
        val chain = certificates.encodePem(template).repeat(257)
        certificates.decodePem(chain).failureOrNull() shouldBe X509Failure.Malformed
    }
})
