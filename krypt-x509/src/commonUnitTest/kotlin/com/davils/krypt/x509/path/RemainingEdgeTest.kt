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

package com.davils.krypt.x509.path

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.x509.AlgorithmIdentifiers
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.X509Failure
import com.davils.krypt.x509.extension.AuthorityKeyIdentifier
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.extension.PolicyConstraints
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.certificates
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.AttributeTypes
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
private val SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.5")
private val AT: ValidationParameters = ValidationParameters(at = NOW)
private val NON_MINIMAL: ByteString = ByteString(0, 1)
private val TOO_LARGE: ByteString = ByteString(1, 0, 0, 0, 0)
private const val LARGE_RSA: Int = 4_096
private const val BAD_PEM: String = """-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
"""

private fun validator(root: Authority): PathValidator = PathValidator(crypto, listOf(TrustAnchor.of(root.certificate)))

class RemainingEdgeTest : FunSpec({
    test("a certificate signed with an unknown algorithm fails its path") {
        val root = Authority.root()
        val leaf = root.issue("leaf").certificate
        val unknown = der {
            sequence {
                sequence {
                    explicit(0) { integer(2L) }
                    integer(DerInteger.of(1L))
                    sequence {
                        objectIdentifier(SHA1_WITH_RSA)
                        nullValue()
                    }
                    raw(root.certificate.subject.encoded)
                    sequence {
                        time(NOW)
                        time(NOW)
                    }
                    raw(leaf.subject.encoded)
                    raw(leaf.subjectPublicKeyInfo)
                }
                sequence {
                    objectIdentifier(SHA1_WITH_RSA)
                    nullValue()
                }
                bitString(BitString(ByteString(1)))
            }
        }
        val certificate = checkNotNull(certificates.decode(unknown).getOrNull())
        certificate.signatureAlgorithm shouldBe null
        val result = validator(root).validate(certificate, parameters = AT)
        (result as PathValidation.Invalid).failure shouldBe PathFailure.AlgorithmNotPermitted
    }

    test("keys the policy forbids do not verify and anchors need readable keys") {
        val root = Authority.root()
        val leaf = root.issue("leaf").certificate
        val noP256 = Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } })
        Certificates(noP256).verifySignature(
            leaf,
            checkNotNull(root.certificate.publicKey),
        ) shouldBe Verification.Invalid
        val rsa = crypto.keys.generate(KeyType.Rsa3072)
        val strictRsa = Crypto(
            environment {
                policy = cryptoPolicy {
                    minimumVerifiedRsaBits = LARGE_RSA
                    minimumRsaBits = LARGE_RSA
                }
            },
        )
        Certificates(strictRsa).verifySignature(leaf, rsa.publicKey) shouldBe Verification.Invalid
        val strict = Certificates(noP256)
        val unreadable = checkNotNull(strict.decode(root.certificate.encoded).getOrNull())
        shouldThrow<IllegalArgumentException> { TrustAnchor.of(unreadable) }
        val anchor = TrustAnchor.of(root.certificate)
        anchor shouldNotBe TrustAnchor(distinguishedName { commonName("other") }, anchor.publicKey)
        anchor shouldNotBe TrustAnchor(anchor.name, rsa.publicKey)
        val hiddenIssuer = unreadable
        CrlRevocationChecker(
            revocationLists,
        ) { _ -> emptyList() }.check(
            certificate = leaf,
            issuer = hiddenIssuer,
            anchor = anchor,
            at = NOW,
        ) shouldBe RevocationStatus.Unknown
    }

    test("lists of other issuers or from the future do not count") {
        val root = Authority.root()
        val leaf = root.issue("leaf").certificate
        val anchor = TrustAnchor.of(root.certificate)
        val other = Authority.root(name = "Other")
        val foreign = revocationLists.issue(other.signer) {
            issuer = other.certificate.subject
            thisUpdate = NOW - 1.days
            nextUpdate = NOW + 1.days
            number = DerInteger.of(1L)
        }
        val future = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW + 1.days
            nextUpdate = NOW + 2.days
            number = DerInteger.of(1L)
        }
        CrlRevocationChecker(
            revocationLists,
        ) { _ -> listOf(foreign, future) }.check(certificate = leaf, issuer = null, anchor = anchor, at = NOW) shouldBe
            RevocationStatus.Unknown
        future.toString() shouldContain "nextUpdate=20"
    }

    test("policies, names and key identifiers have their last cases") {
        val root = Authority.root()
        val ca = root.issue("ca", isCa = true, extensions = {
            basicConstraints(isCa = true)
            policyConstraints(PolicyConstraints(inhibitPolicyMapping = 1))
            nameConstraints(
                NameConstraints(
                    permitted = listOf(GeneralName.Dns(HOST), GeneralName.Email(HOST)),
                    excluded = listOf(GeneralName.Uri(HOST)),
                ),
            )
            subjectKeyIdentifier(utf8("ca"))
        })
        val leaf = ca.issue(HOST, extensions = {
            policyConstraints(PolicyConstraints(inhibitPolicyMapping = 1))
            subjectAlternativeNames(listOf(GeneralName.Dns(HOST), GeneralName.Email("ops@$HOST")))
            authorityKeyIdentifier(utf8("ca"))
        })
        validator(root).validate(leaf.certificate, listOf(ca.certificate), AT).isValid shouldBe true
        val noKeyId = root.issue("ca", isCa = true)
        val withAuthorityKey = noKeyId.issue(HOST, extensions = { authorityKeyIdentifier(utf8("anything")) })
        validator(root).validate(withAuthorityKey.certificate, listOf(noKeyId.certificate), AT).isValid shouldBe true
        val first = root.issue("first", isCa = true)
        val second = first.issue("second", isCa = true)
        val wrongLeaf = Authority.root("second").issue(HOST)
        val result = validator(root).validate(wrongLeaf.certificate, listOf(second.certificate, first.certificate), AT)
        result.isValid shouldBe false
    }

    test("remaining encodings are refused or read leniently") {
        fun extensionWith(id: ObjectIdentifier, value: ByteString): Extension = Extension(id, false, value)
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = crypto.signatures.signer(pair.privateKey)

        suspend fun issued(extension: Extension) = certificates.issue(signer) {
            publicKey = pair.publicKey
            notBefore = NOW
            notAfter = NOW
            extensions { add(extension) }
        }
        issued(extensionWith(ExtensionIds.BasicConstraints, der { sequence { boolean(false) } })).isCa shouldBe false
        listOf(
            extensionWith(ExtensionIds.CertificatePolicies, der { sequence { } }),
            extensionWith(
                ExtensionIds.PolicyConstraints,
                der { sequence { element(Tag.context(number = 0, isConstructed = false), NON_MINIMAL) } },
            ),
            extensionWith(
                ExtensionIds.PolicyConstraints,
                der { sequence { element(Tag.context(number = 0, isConstructed = false), TOO_LARGE) } },
            ),
        ).forEach { extension -> shouldThrow<IllegalStateException> { issued(extension) } }
        val authority = AuthorityKeyIdentifier(null)
        authority.toString() shouldBe "AuthorityKeyIdentifier(none)"
        val serial = distinguishedName { attribute(AttributeTypes.SerialNumber, "aZ9 -'()+,./:=?") }
        val serialAttribute = serial.names
            .single()
            .attributes
            .single()
        serialAttribute.tag shouldBe Tag.PrintableString
        val underscored = distinguishedName { attribute(AttributeTypes.SerialNumber, "a_b") }
        val underscoredAttribute = underscored.names
            .single()
            .attributes
            .single()
        underscoredAttribute.tag shouldBe Tag.Utf8String
        shouldThrow<IllegalArgumentException> { distinguishedName { country("D1") } }
        val firstName = distinguishedName { attribute(AttributeTypes.CommonName, "a") }
        val first = firstName.names
            .single()
            .attributes
            .single()
        val secondName = distinguishedName { attribute(AttributeTypes.UserId, "a") }
        val second = secondName.names
            .single()
            .attributes
            .single()
        first shouldNotBe second
        val good = certificates.encodePem(Authority.root().certificate)
        val bad = BAD_PEM
        certificates.decodePem(good + bad).failureOrNull() shouldBe X509Failure.Malformed
        AlgorithmIdentifiers.encode(SignatureAlgorithm.Ed25519).size shouldNotBe 0
    }
})
