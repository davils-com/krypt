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

package com.davils.krypt.x509.crl

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers
import com.davils.krypt.x509.X509Failure
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val UNKNOWN_REASON: Long = 7L
private const val HOST: String = "example.com"

private val ALGORITHM: ByteString = AlgorithmIdentifiers.encode(SignatureAlgorithm.EcdsaSha256)

private fun list(outer: ByteString = ALGORITHM, unusedBits: Int = 0, body: DerWriter.() -> Unit = {}): ByteString =
    der {
        sequence {
            sequence {
                integer(1L)
                raw(ALGORITHM)
                raw(distinguishedName { commonName("CA") }.encoded)
                time(NOW)
                body()
            }
            raw(outer)
            bitString(BitString(ByteString(0), unusedBits))
        }
    }

private fun entry(extensions: DerWriter.() -> Unit): DerWriter.() -> Unit = {
    sequence {
        sequence {
            integer(1L)
            time(NOW)
            extensions()
        }
    }
}

private fun extension(id: ObjectIdentifier, value: ByteString): DerWriter.() -> Unit = {
    sequence {
        sequence {
            objectIdentifier(id)
            octetString(value)
        }
    }
}

private fun point(value: DerWriter.() -> Unit): DerWriter.() -> Unit = {
    explicit(0) { extension(ExtensionIds.IssuingDistributionPoint, der { sequence(value) })() }
}

class HostileListsTest : FunSpec({
    test("lists that break their structure are refused") {
        revocationLists.decode(list()).getOrNull()?.entries shouldBe emptyList()
        val cases = listOf(
            list(unusedBits = 1),
            list(outer = AlgorithmIdentifiers.encode(SignatureAlgorithm.Ed25519)),
            list { nullValue() },
            list { sequence { } },
            list(body = entry(extension(ExtensionIds.ReasonCode, der { integer(UNKNOWN_REASON, Tag.Enumerated) }))),
            list(body = entry { sequence { nullValue() } }),
            list(body = point { boolean(false, Tag.context(number = 1, isConstructed = false)) }),
            list(body = point { boolean(true, Tag.context(number = 5, isConstructed = false)) }),
            list(
                body = point {
                    boolean(true, Tag.context(number = 1, isConstructed = false))
                    boolean(true, Tag.context(number = 2, isConstructed = false))
                },
            ),
        )
        cases.forEach { encoded -> revocationLists.decode(encoded).failureOrNull() shouldBe X509Failure.Malformed }
        revocationLists.decodePem("-----BEGIN X509 CRL-----\n!!\n").failureOrNull() shouldBe X509Failure.Malformed
    }

    test("indirect entries and relative point names are read") {
        val issuer = der { sequence { ia5String(HOST, Tag.context(number = 2, isConstructed = false)) } }
        val indirect = list(body = entry(extension(ExtensionIds.CertificateIssuer, issuer)))
        val outcome114 = revocationLists.decode(
            indirect,
        )
        outcome114
            .getOrNull()
            ?.find(DerInteger.of(1L))
            ?.certificateIssuer shouldBe listOf(GeneralName.Dns(HOST))
        val relative = list(
            body = point {
                explicit(
                    0,
                ) { constructed(Tag.context(number = 1, isConstructed = true)) { sequence { } } }
            },
        )
        revocationLists
            .decode(relative)
            .getOrNull()
            ?.issuingDistributionPoint
            ?.names shouldBe emptyList()
        utf8(HOST).size shouldBe HOST.length
    }
})
