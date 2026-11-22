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

package com.davils.krypt.x509.path

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.extension.PolicyConstraints
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private const val HOST: String = "api.example.com"
private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.1")
private val OTHER: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.2")
private val UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.9")

private fun validator(root: Authority, revocation: RevocationChecker? = null): PathValidator =
    PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(root.certificate)), revocation = revocation)

private fun failureOf(result: PathValidation): PathFailure? = (result as? PathValidation.Invalid)?.failure

private const val DOMAIN: String = "example.com"
private const val SUBDOMAINS: String = ".example.com"
private const val ORGANIZATION: String = "Davils"

private val AT: ValidationParameters = ValidationParameters(at = NOW)

class PathValidatorTest : FunSpec({
    test("a path through intermediates in any order is valid") {
        val root = Authority.root()
        val first = root.issue("first", isCa = true)
        val second = first.issue("second", isCa = true)
        val leaf = second.issue(HOST)
        val result = validator(root).validate(
            leaf.certificate,
            listOf(root.certificate, first.certificate, second.certificate),
            AT,
        )
        val valid = result.shouldBeInstanceOf<PathValidation.Valid>()
        valid.isValid shouldBe true
        valid.path shouldBe listOf(leaf.certificate, second.certificate, first.certificate)
        valid.anchor.certificate shouldBe root.certificate
        valid.policies shouldBe emptySet()
        valid.toString() shouldContain "3 certificates"
        validator(root).toString() shouldBe "PathValidator(1 anchors)"
        validator(root).validate(root.certificate, parameters = AT).isValid shouldBe true
        val partial = validator(root).validate(leaf.certificate, listOf(first.certificate), AT)
        failureOf(partial) shouldBe PathFailure.NoTrustedPath
        val stranger = Authority.root("Stranger")
        val strange = validator(stranger).validate(leaf.certificate, parameters = AT)
        val invalid = strange.shouldBeInstanceOf<PathValidation.Invalid>()
        invalid.failure shouldBe PathFailure.NoTrustedPath
        invalid.isValid shouldBe false
        invalid.toString() shouldContain "NoTrustedPath"
    }

    test("signatures, validity and authority are checked on every certificate") {
        val root = Authority.root()
        val impostor = Authority.root()
        val forged = impostor.issue(HOST)
        failureOf(validator(root).validate(forged.certificate, parameters = AT)) shouldBe PathFailure.BadSignature
        val expired = root.issue(HOST, notBefore = NOW - 10.days, notAfter = NOW - 1.days)
        failureOf(validator(root).validate(expired.certificate, parameters = AT)) shouldBe PathFailure.Expired
        val endEntity = root.issue("end entity")
        val below = endEntity.issue(HOST)
        failureOf(
            validator(root).validate(below.certificate, listOf(endEntity.certificate), AT),
        ) shouldBe PathFailure.NotAnAuthority
        val noSign = root.issue(
            "no sign",
            isCa = true,
            extensions = {
                basicConstraints(isCa = true)
                keyUsage(setOf(KeyUsage.CrlSign))
            },
        )
        val belowNoSign = noSign.issue(HOST)
        failureOf(
            validator(root).validate(belowNoSign.certificate, listOf(noSign.certificate), AT),
        ) shouldBe PathFailure.KeyUsage
        val critical = root.issue(HOST, extensions = { add(Extension(UNKNOWN, true, der { nullValue() })) })
        failureOf(
            validator(root).validate(critical.certificate, parameters = AT),
        ) shouldBe PathFailure.UnknownCriticalExtension
        validator(root).validate(endEntity.certificate).isValid shouldBe false
    }

    test("path lengths and the limits bound the path") {
        val root = Authority.root(
            extensions = {
                basicConstraints(isCa = true, pathLength = 0)
                keyUsage(setOf(KeyUsage.KeyCertSign))
            },
        )
        val intermediate = root.issue("intermediate", isCa = true)
        val leaf = intermediate.issue(HOST)
        validator(root).validate(intermediate.certificate, parameters = AT).isValid shouldBe true
        val zero = Authority.root()
        val first = zero.issue(
            "first",
            isCa = true,
            extensions = {
                basicConstraints(isCa = true, pathLength = 0)
                keyUsage(setOf(KeyUsage.KeyCertSign))
            },
        )
        val second = first.issue("second", isCa = true)
        val deep = second.issue(HOST)
        failureOf(
            validator(zero).validate(deep.certificate, listOf(first.certificate, second.certificate), AT),
        ) shouldBe PathFailure.PathTooLong
        val short = PathValidator(
            crypto,
            listOf(TrustAnchor.of(zero.certificate)),
            limits = X509Limits(maximumPathLength = 1),
        )
        short.validate(deep.certificate, listOf(first.certificate, second.certificate), AT).isValid shouldBe false
        val tight = PathValidator(
            crypto,
            listOf(TrustAnchor.of(zero.certificate)),
            limits = X509Limits(maximumPathAttempts = 1),
        )
        tight.validate(deep.certificate, listOf(first.certificate, second.certificate), AT).isValid shouldBe false
        validator(root).validate(leaf.certificate, listOf(intermediate.certificate), AT).isValid shouldBe true
    }

    test("purposes are checked on the end entity and the authorities") {
        val root = Authority.root()
        val server = root.issue(
            HOST,
            extensions = {
                basicConstraints(isCa = false)
                extendedKeyUsage(listOf(KeyPurposes.ServerAuth))
            },
        )
        val asServer = ValidationParameters(at = NOW, purpose = KeyPurposes.ServerAuth)
        val asClient = ValidationParameters(at = NOW, purpose = KeyPurposes.ClientAuth)
        validator(root).validate(server.certificate, parameters = asServer).isValid shouldBe true
        failureOf(validator(root).validate(server.certificate, parameters = asClient)) shouldBe PathFailure.Purpose
        val restricted = root.issue("restricted", isCa = true, extensions = {
            basicConstraints(isCa = true)
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth))
        })
        val client = restricted.issue("client")
        failureOf(
            validator(root).validate(client.certificate, listOf(restricted.certificate), asClient),
        ) shouldBe PathFailure.Purpose
        val any = root.issue(
            "any",
            isCa = true,
            extensions = {
                basicConstraints(isCa = true)
                extendedKeyUsage(listOf(KeyPurposes.Any))
            },
        )
        validator(root).validate(any.issue("c").certificate, listOf(any.certificate), asClient).isValid shouldBe true
    }

    test("name constraints of the anchor and the authorities hold for every name") {
        val ip = checkNotNull(GeneralName.IpAddress.parseOrNull("10.0.0.0"))
        val net = GeneralName.IpAddress(
            ByteString(ip.bytes.toByteArray() + byteArrayOf(-1, 0, 0, 0)),
        )
        val constraints = NameConstraints(
            permitted = listOf(
                GeneralName.Dns(DOMAIN),
                net,
                GeneralName.Email(SUBDOMAINS),
                GeneralName.Uri(SUBDOMAINS),
                GeneralName.Directory(distinguishedName { organization(ORGANIZATION) }),
            ),
            excluded = listOf(GeneralName.Dns("secret.example.com"), GeneralName.Email("boss@mail.example.com")),
        )
        val root = Authority.root()
        val constrained = root.issue(
            name = "constrained",
            isCa = true,
            subject = distinguishedName {
                organization(
                    ORGANIZATION,
                )
                commonName("CA")
            },
            extensions = {
                basicConstraints(isCa = true)
                nameConstraints(constraints)
            },
        )

        suspend fun leafWith(
            names: List<GeneralName>,
            subject: DistinguishedName = distinguishedName {
                organization(
                    ORGANIZATION,
                )
                commonName("x")
            },
        ) = constrained.issue("leaf", subject = subject, extensions = { subjectAlternativeNames(names) }).certificate

        suspend fun isValid(certificate: Certificate): Boolean =
            validator(root).validate(certificate, listOf(constrained.certificate), AT).isValid
        isValid(
            leafWith(
                listOf(GeneralName.Dns("a.example.com"), checkNotNull(GeneralName.IpAddress.parseOrNull("10.1.2.3"))),
            ),
        ) shouldBe true
        isValid(
            leafWith(
                listOf(GeneralName.Email("ops@mail.example.com"), GeneralName.Uri("https://api.example.com:8443/x")),
            ),
        ) shouldBe true
        isValid(leafWith(listOf(GeneralName.Dns("example.org")))) shouldBe false
        isValid(leafWith(listOf(GeneralName.Dns("x.secret.example.com")))) shouldBe false
        isValid(leafWith(listOf(checkNotNull(GeneralName.IpAddress.parseOrNull("11.0.0.1"))))) shouldBe false
        isValid(leafWith(listOf(checkNotNull(GeneralName.IpAddress.parseOrNull("::1"))))) shouldBe false
        isValid(leafWith(listOf(GeneralName.Email("boss@mail.example.com")))) shouldBe false
        isValid(leafWith(listOf(GeneralName.Email("a@example.org")))) shouldBe false
        isValid(leafWith(listOf(GeneralName.Uri("urn:isbn:123")))) shouldBe false
        isValid(leafWith(listOf(GeneralName.Uri("https://[::1]/")))) shouldBe false
        isValid(
            leafWith(listOf(GeneralName.Dns("a.example.com")), distinguishedName { organization("Evil") }),
        ) shouldBe false
        isValid(leafWith(listOf(GeneralName.RegisteredId(UNKNOWN)))) shouldBe true
        val anchorConstraints = NameConstraints(
            permitted = listOf(
                GeneralName.Dns(".example.com"),
                GeneralName.Email("ops@example.com"),
                GeneralName.Uri("example.com"),
            ),
        )
        val anchor = TrustAnchor(root.certificate.subject, checkNotNull(root.certificate.publicKey), anchorConstraints)
        val anchored = PathValidator(crypto, listOf(anchor))
        val bareDomain = root.issue("x", extensions = { subjectAlternativeNames(listOf(GeneralName.Dns(DOMAIN))) })
        anchored.validate(bareDomain.certificate, parameters = AT).isValid shouldBe false
        val mailAndUri = root.issue(
            "x",
            extensions = {
                subjectAlternativeNames(
                    listOf(GeneralName.Email("ops@example.com"), GeneralName.Uri("http://user@example.com/")),
                )
            },
        )
        anchored.validate(mailAndUri.certificate, parameters = AT).isValid shouldBe true
    }

    test("certificate policies are processed along the path") {
        val root = Authority.root()
        val policies = root.issue("policies", isCa = true, extensions = {
            basicConstraints(isCa = true)
            certificatePolicies(listOf(POLICY))
        })
        val leaf = policies.issue(HOST, extensions = { certificatePolicies(listOf(POLICY, OTHER)) })
        val explicit = ValidationParameters(at = NOW, isExplicitPolicyRequired = true, initialPolicies = setOf(POLICY))
        val explicitResult = validator(root).validate(leaf.certificate, listOf(policies.certificate), explicit)
        explicitResult.shouldBeInstanceOf<PathValidation.Valid>().policies shouldBe setOf(POLICY)
        val wrong = ValidationParameters(at = NOW, isExplicitPolicyRequired = true, initialPolicies = setOf(OTHER))
        failureOf(
            validator(root).validate(leaf.certificate, listOf(policies.certificate), wrong),
        ) shouldBe PathFailure.Policy
        val bare = policies.issue(HOST)
        failureOf(
            validator(root).validate(bare.certificate, listOf(policies.certificate), explicit),
        ) shouldBe PathFailure.Policy
        val bareResult = validator(root).validate(bare.certificate, listOf(policies.certificate), AT)
        bareResult.shouldBeInstanceOf<PathValidation.Valid>().policies shouldBe emptySet()
        val requiring = root.issue("requiring", isCa = true, extensions = {
            basicConstraints(isCa = true)
            policyConstraints(PolicyConstraints(requireExplicitPolicy = 0))
        })
        failureOf(
            validator(root).validate(requiring.issue(HOST).certificate, listOf(requiring.certificate), AT),
        ) shouldBe PathFailure.Policy
        val any = root.issue("any", isCa = true, extensions = {
            basicConstraints(isCa = true)
            certificatePolicies(listOf(KeyPurposes.AnyPolicy))
            add(
                Extension(
                    ExtensionIds.PolicyMappings,
                    true,
                    der {
                        sequence {
                            sequence {
                                objectIdentifier(POLICY)
                                objectIdentifier(OTHER)
                            }
                        }
                    },
                ),
            )
            add(Extension(ExtensionIds.InhibitAnyPolicy, true, der { integer(0L) }))
        })
        val mapped = any.issue(HOST, extensions = { certificatePolicies(listOf(OTHER)) })
        validator(root).validate(mapped.certificate, listOf(any.certificate), AT).isValid shouldBe true
        val noMapping = ValidationParameters(at = NOW, isPolicyMappingInhibited = true, isAnyPolicyInhibited = true)
        validator(root).validate(mapped.certificate, listOf(any.certificate), noMapping).isValid shouldBe true
        val toAny = root.issue("toAny", isCa = true, extensions = {
            basicConstraints(isCa = true)
            certificatePolicies(listOf(POLICY))
            add(
                Extension(
                    ExtensionIds.PolicyMappings,
                    true,
                    der {
                        sequence {
                            sequence {
                                objectIdentifier(POLICY)
                                objectIdentifier(KeyPurposes.AnyPolicy)
                            }
                        }
                    },
                ),
            )
        })
        failureOf(
            validator(root).validate(toAny.issue(HOST).certificate, listOf(toAny.certificate), AT),
        ) shouldBe PathFailure.Policy
        val leafRequires = policies.issue(
            "leaf",
            extensions = { policyConstraints(PolicyConstraints(requireExplicitPolicy = 0)) },
        )
        failureOf(
            validator(root).validate(leafRequires.certificate, listOf(policies.certificate), AT),
        ) shouldBe PathFailure.Policy
        shouldThrow<IllegalArgumentException> { ValidationParameters(initialPolicies = emptySet()) }
        AT shouldBe ValidationParameters(at = NOW)
        AT.hashCode() shouldBe ValidationParameters(at = NOW).hashCode()
        AT.toString() shouldContain "ValidationParameters"
        ValidationParameters() shouldNotBe AT
        AT shouldNotBe Any()
    }

    test("revocation is asked for every certificate") {
        val root = Authority.root()
        val leaf = root.issue(HOST)
        val revoked = RevocationChecker { _, _, _, _ -> RevocationStatus.Revoked }
        val unknown = RevocationChecker { _, _, _, _ -> RevocationStatus.Unknown }
        failureOf(validator(root, revoked).validate(leaf.certificate, parameters = AT)) shouldBe PathFailure.Revoked
        failureOf(
            validator(root, unknown).validate(leaf.certificate, parameters = AT),
        ) shouldBe PathFailure.RevocationUnknown
        val soft = ValidationParameters(at = NOW, isRevocationRequired = false)
        validator(root, unknown).validate(leaf.certificate, parameters = soft).isValid shouldBe true
        validator(
            root,
            RevocationChecker { _, _, _, _ -> RevocationStatus.Good },
        ).validate(leaf.certificate, parameters = AT).isValid shouldBe true
    }

    test("anchors compare by name and key") {
        val root = Authority.root()
        val anchor = TrustAnchor.of(root.certificate)
        anchor shouldBe TrustAnchor(root.certificate.subject, checkNotNull(root.certificate.publicKey))
        anchor.hashCode() shouldBe TrustAnchor(
            root.certificate.subject,
            root.certificate.publicKey,
        ).hashCode()
        anchor shouldNotBe Any()
        anchor.toString() shouldBe "TrustAnchor(CN=Root)"
    }
})
