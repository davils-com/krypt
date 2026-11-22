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

package com.davils.krypt.x509.extension

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.certificates
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private const val HOST: String = "example.com"
private const val URL: String = "http://crl.example.com/root.crl"
private const val OCSP: String = "http://ocsp.example.com"
private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.1")
private val OTHER_POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.2")
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.9")
private const val SKIP: Int = 2
private const val FEATURE: Int = 5

private suspend fun issued(block: ExtensionsBuilder.() -> Unit): Extensions {
    val pair = crypto.keys.generate(KeyType.P256)
    val certificate = certificates.issue(crypto.signatures.signer(pair.privateKey)) {
        subject { commonName("extensions") }
        publicKey = pair.publicKey
        notBefore = NOW
        notAfter = NOW + 1.days
        extensions(block)
    }
    return certificate.extensions
}

private const val SERIAL: Long = 7L
private const val REASONS: Int = 10
private const val REASON_BITS: Byte = -128

private suspend fun issueWith(extension: Extension): Certificate {
    val pair = crypto.keys.generate(KeyType.P256)
    val signer = crypto.signatures.signer(pair.privateKey)
    return certificates.issue(signer) {
        publicKey = pair.publicKey
        notBefore = NOW
        notAfter = NOW
        extensions { add(extension) }
    }
}

class ExtensionsTest : FunSpec({
    test("every extension krypt writes is read back") {
        val identifier = utf8("key-id-of-twenty-by")
        val names = listOf(GeneralName.Dns(HOST), GeneralName.Email("ops@$HOST"), GeneralName.Uri("spiffe://$HOST/a"))
        val ip = checkNotNull(GeneralName.IpAddress.parseOrNull("10.0.0.0"))
        val net = GeneralName.IpAddress(ByteString(ip.bytes.toByteArray() + byteArrayOf(-1, 0, 0, 0)))
        val constraints = NameConstraints(
            permitted = listOf(GeneralName.Dns(HOST), net),
            excluded = listOf(GeneralName.Directory(distinguishedName { organization("Evil") })),
        )
        val points = listOf(
            DistributionPoint(names = listOf(GeneralName.Uri(URL)), reasons = setOf(RevocationReason.KeyCompromise)),
        )
        val access = listOf(
            AccessDescription(KeyPurposes.OcspAccess, GeneralName.Uri(OCSP)),
            AccessDescription(KeyPurposes.CaIssuersAccess, GeneralName.Uri(URL)),
        )
        val extensions = issued {
            basicConstraints(isCa = true, pathLength = 1)
            keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.DecipherOnly))
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth, KeyPurposes.OcspSigning))
            subjectAlternativeNames(names)
            subjectKeyIdentifier(identifier)
            authorityKeyIdentifier(identifier)
            nameConstraints(constraints)
            certificatePolicies(listOf(POLICY, OTHER_POLICY))
            policyConstraints(PolicyConstraints(requireExplicitPolicy = 0, inhibitPolicyMapping = 1))
            crlDistributionPoints(points)
            authorityInformationAccess(access)
            mustStaple()
            ocspNoCheck()
        }
        extensions.basicConstraints shouldBe BasicConstraints(isCa = true, pathLength = 1)
        extensions.keyUsage shouldBe setOf(KeyUsage.KeyCertSign, KeyUsage.DecipherOnly)
        extensions.extendedKeyUsage shouldBe listOf(KeyPurposes.ServerAuth, KeyPurposes.OcspSigning)
        extensions.subjectAlternativeNames shouldBe names
        extensions.subjectKeyIdentifier shouldBe identifier
        extensions.authorityKeyIdentifier shouldBe AuthorityKeyIdentifier(identifier)
        extensions.nameConstraints shouldBe constraints
        extensions.certificatePolicies shouldBe listOf(POLICY, OTHER_POLICY)
        extensions.policyConstraints shouldBe PolicyConstraints(requireExplicitPolicy = 0, inhibitPolicyMapping = 1)
        extensions.crlDistributionPoints shouldBe points
        extensions.authorityInformationAccess shouldBe access
        extensions.tlsFeatures shouldBe setOf(FEATURE)
        extensions.isOcspNoCheck shouldBe true
        extensions.unknownCritical shouldBe emptyList()
        extensions[ExtensionIds.KeyUsage]?.isCritical shouldBe true
        extensions[UNKNOWN] shouldBe null
        extensions.toString() shouldContain "2.5.29.19"
        extensions shouldBe extensions
        extensions shouldNotBe Any()
        extensions.hashCode() shouldBe extensions.all.hashCode()
    }

    test("absent extensions read as nothing and unknown critical ones are listed") {
        val extensions = issued { add(Extension(id = UNKNOWN, isCritical = true, value = der { nullValue() })) }
        listOf(
            extensions.basicConstraints,
            extensions.keyUsage,
            extensions.extendedKeyUsage,
            extensions.subjectKeyIdentifier,
        ).forEach { value -> value shouldBe null }
        extensions.subjectAlternativeNames shouldBe emptyList()
        extensions.issuerAlternativeNames shouldBe emptyList()
        extensions.policyMappings shouldBe emptyList()
        extensions.freshestCrl shouldBe emptyList()
        extensions.subjectInformationAccess shouldBe emptyList()
        extensions.inhibitAnyPolicy shouldBe null
        extensions.isOcspNoCheck shouldBe false
        extensions.unknownCritical shouldBe listOf(UNKNOWN)
    }

    test("extensions written by hand are read with every option") {
        val issuer = GeneralName.Directory(distinguishedName { commonName("issuer") })
        val authority = der {
            sequence {
                octetString(utf8("id"), Tag.context(number = 0, isConstructed = false))
                constructed(Tag.context(number = 1, isConstructed = true)) {
                    explicit(4) { raw(issuer.name.encoded) }
                }
                integer(DerInteger.of(SERIAL), Tag.context(number = 2, isConstructed = false))
            }
        }
        val mappings = der {
            sequence {
                sequence {
                    objectIdentifier(POLICY)
                    objectIdentifier(OTHER_POLICY)
                }
            }
        }
        val points = der {
            sequence {
                sequence {
                    explicit(0) { constructed(Tag.context(number = 1, isConstructed = true)) { sequence { } } }
                    constructed(
                        Tag.context(number = 2, isConstructed = true),
                    ) { explicit(4) { raw(issuer.name.encoded) } }
                }
            }
        }
        val policies = der {
            sequence {
                sequence {
                    objectIdentifier(POLICY)
                    sequence { }
                }
            }
        }
        val extensions = issued {
            add(Extension(ExtensionIds.AuthorityKeyIdentifier, false, authority))
            add(Extension(ExtensionIds.PolicyMappings, true, mappings))
            add(Extension(ExtensionIds.InhibitAnyPolicy, true, der { integer(SKIP.toLong()) }))
            add(Extension(ExtensionIds.FreshestCrl, false, points))
            add(Extension(ExtensionIds.CertificatePolicies, false, policies))
            add(
                Extension(
                    ExtensionIds.IssuerAlternativeName,
                    false,
                    der { sequence { ia5String(HOST, Tag.context(number = 2, isConstructed = false)) } },
                ),
            )
            add(
                Extension(
                    ExtensionIds.SubjectInformationAccess,
                    false,
                    der {
                        sequence {
                            sequence {
                                objectIdentifier(
                                    POLICY,
                                )
                                ia5String(URL, Tag.context(number = 6, isConstructed = false))
                            }
                        }
                    },
                ),
            )
        }
        extensions.authorityKeyIdentifier shouldBe AuthorityKeyIdentifier(
            utf8("id"),
            listOf(issuer),
            DerInteger.of(SERIAL),
        )
        extensions.policyMappings shouldBe listOf(PolicyMapping(issuerPolicy = POLICY, subjectPolicy = OTHER_POLICY))
        extensions.inhibitAnyPolicy shouldBe SKIP
        extensions.freshestCrl shouldBe listOf(DistributionPoint(names = emptyList(), crlIssuer = listOf(issuer)))
        extensions.certificatePolicies shouldBe listOf(POLICY)
        extensions.issuerAlternativeNames shouldBe listOf(GeneralName.Dns(HOST))
        extensions.subjectInformationAccess.single().method shouldBe POLICY
    }

    test("malformed extension values make the certificate unreadable") {
        val malformed = mapOf(
            ExtensionIds.BasicConstraints to der { sequence { integer(1L) } },
            ExtensionIds.KeyUsage to der {
                bitString(
                    BitString(ByteString(0)),
                )
            },
            ExtensionIds.ExtendedKeyUsage to der { sequence { } },
            ExtensionIds.SubjectAlternativeName to der { sequence { } },
            ExtensionIds.NameConstraints to der { sequence { } },
            ExtensionIds.CertificatePolicies to der {
                sequence {
                    sequence {
                        objectIdentifier(
                            POLICY,
                        )
                    }
                    sequence { objectIdentifier(POLICY) }
                }
            },
            ExtensionIds.PolicyMappings to der { sequence { } },
            ExtensionIds.PolicyConstraints to der { sequence { } },
            ExtensionIds.CrlDistributionPoints to der { sequence { } },
            ExtensionIds.AuthorityInformationAccess to der { sequence { } },
            ExtensionIds.SubjectKeyIdentifier to der { integer(1L) },
            ExtensionIds.AuthorityKeyIdentifier to der {
                sequence {
                    integer(
                        DerInteger.of(1L),
                        Tag.context(number = 2, isConstructed = false),
                    )
                    nullValue()
                }
            },
            ExtensionIds.SubjectAlternativeName to der {
                sequence {
                    ia5String(
                        HOST,
                        Tag.context(number = 9, isConstructed = false),
                    )
                }
            },
        )
        malformed.forEach { (id, value) ->
            shouldThrow<IllegalStateException> { issueWith(Extension(id = id, isCritical = false, value = value)) }
        }
        val subtreeWithMinimum = der {
            sequence {
                constructed(Tag.context(number = 0, isConstructed = true)) {
                    sequence {
                        ia5String(HOST, Tag.context(number = 2, isConstructed = false))
                        integer(1L, Tag.context(number = 0, isConstructed = false))
                    }
                }
            }
        }
        shouldThrow<IllegalStateException> {
            issueWith(
                Extension(ExtensionIds.NameConstraints, true, subtreeWithMinimum),
            )
        }
        val reasonsOnly = der {
            sequence {
                sequence {
                    bitString(BitString(ByteString(REASON_BITS)), Tag.context(number = 1, isConstructed = false))
                }
            }
        }
        issueWith(
            Extension(ExtensionIds.CrlDistributionPoints, false, reasonsOnly),
        ).extensions.crlDistributionPoints.size shouldBe 1
    }

    test("values compare, hash and show themselves") {
        val values: List<Any> = listOf(
            BasicConstraints(isCa = false),
            AuthorityKeyIdentifier(null),
            NameConstraints(excluded = listOf(GeneralName.Dns(HOST))),
            PolicyMapping(issuerPolicy = POLICY, subjectPolicy = OTHER_POLICY),
            PolicyConstraints(requireExplicitPolicy = 1),
            DistributionPoint(names = listOf(GeneralName.Uri(URL))),
            AccessDescription(KeyPurposes.OcspAccess, GeneralName.Uri(OCSP)),
            Extension(UNKNOWN, false, ByteString()),
        )
        values.forEach { value ->
            value shouldNotBe Any()
            value.hashCode() shouldBe value.hashCode()
            value.toString().length shouldNotBe 0
        }
        BasicConstraints(isCa = true).toString() shouldBe "BasicConstraints(ca=true, pathLength=none)"
        AuthorityKeyIdentifier(utf8("a")).toString() shouldBe "AuthorityKeyIdentifier(61)"
        AuthorityKeyIdentifier(null).toString() shouldBe "AuthorityKeyIdentifier(none)"
        shouldThrow<IllegalArgumentException> { BasicConstraints(isCa = false, pathLength = 1) }
        shouldThrow<IllegalArgumentException> { BasicConstraints(isCa = true, pathLength = -1) }
        shouldThrow<IllegalArgumentException> { NameConstraints() }
        shouldThrow<IllegalArgumentException> { PolicyConstraints() }
        shouldThrow<IllegalArgumentException> { PolicyConstraints(requireExplicitPolicy = -1) }
        shouldThrow<IllegalArgumentException> { PolicyConstraints(inhibitPolicyMapping = -1) }
        val builder = ExtensionsBuilder()
        builder.ocspNoCheck()
        shouldThrow<IllegalArgumentException> { builder.ocspNoCheck() }
        shouldThrow<IllegalArgumentException> { builder.keyUsage(emptySet()) }
        shouldThrow<IllegalArgumentException> { builder.extendedKeyUsage(emptyList()) }
        shouldThrow<IllegalArgumentException> { builder.subjectAlternativeNames(emptyList()) }
        shouldThrow<IllegalArgumentException> { builder.certificatePolicies(listOf(POLICY, POLICY)) }
        shouldThrow<IllegalArgumentException> { builder.crlDistributionPoints(emptyList()) }
        shouldThrow<IllegalArgumentException> { builder.authorityInformationAccess(emptyList()) }
        RevocationReason.entries.size shouldBe REASONS
    }
})
