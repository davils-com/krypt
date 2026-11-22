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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
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
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private const val HOST: String = "api.example.com"
private val POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.1")
private val OTHER: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.2")
private val AT: ValidationParameters = ValidationParameters(at = NOW)

private fun validator(root: Authority, limits: X509Limits = X509Limits.Default): PathValidator =
    PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(root.certificate)), limits = limits)

private fun failureOf(result: PathValidation): PathFailure? = (result as? PathValidation.Invalid)?.failure

class PathEdgeTest : FunSpec({
    test("algorithms and keys the policy forbids fail the path") {
        val root = Authority.root()
        val leaf = root.issue(HOST)
        val cnsa = PathValidator(
            Crypto(environment { policy = CryptoPolicy.Cnsa2 }),
            listOf(TrustAnchor.of(root.certificate)),
        )
        failureOf(cnsa.validate(leaf.certificate, parameters = AT)) shouldBe PathFailure.AlgorithmNotPermitted
        val noP256 = Certificates(Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } }))
        val unreadable = checkNotNull(noP256.decode(leaf.certificate.encoded).getOrNull())
        unreadable.publicKey shouldBe null
        failureOf(validator(root).validate(unreadable, parameters = AT)) shouldBe PathFailure.AlgorithmNotPermitted
        val intermediate = root.issue("intermediate", isCa = true)
        val below = intermediate.issue(HOST)
        val hidden = checkNotNull(noP256.decode(intermediate.certificate.encoded).getOrNull())
        failureOf(
            validator(root).validate(below.certificate, listOf(hidden), AT),
        ) shouldBe PathFailure.AlgorithmNotPermitted
        val rsa = Authority.root(type = KeyType.Rsa3072)
        validator(rsa).validate(rsa.issue(HOST).certificate, parameters = AT).isValid shouldBe true
    }

    test("a re-keyed authority issues under its own name") {
        val root = Authority.root()
        val ca = root.issue("ca", isCa = true, extensions = {
            basicConstraints(isCa = true, pathLength = 0)
            certificatePolicies(listOf(KeyPurposes.AnyPolicy))
        })
        val rekeyed = ca.issue("ca", isCa = true, extensions = {
            basicConstraints(isCa = true, pathLength = 0)
            certificatePolicies(listOf(KeyPurposes.AnyPolicy))
        })
        val leaf = rekeyed.issue(HOST, extensions = { certificatePolicies(listOf(POLICY)) })
        val noAny = ValidationParameters(at = NOW, isAnyPolicyInhibited = true)
        val outcome96 = validator(root).validate(
            leaf.certificate,
            listOf(ca.certificate, rekeyed.certificate),
            AT,
        )
        outcome96.isValid shouldBe true
        val outcome102 = validator(root).validate(
            leaf.certificate,
            listOf(ca.certificate, rekeyed.certificate),
            noAny,
        )
        outcome102.isValid shouldBe true
    }

    test("key identifiers steer path building and the budget ends it") {
        val root = Authority.root()
        val identified = root.issue("ca", isCa = true, extensions = {
            basicConstraints(isCa = true)
            subjectKeyIdentifier(utf8("right"))
        })
        val other = root.issue("ca", isCa = true, extensions = {
            basicConstraints(isCa = true)
            subjectKeyIdentifier(utf8("wrong"))
        })
        val leaf = identified.issue(HOST, extensions = { authorityKeyIdentifier(utf8("right")) })
        val outcome121 = validator(root).validate(
            leaf.certificate,
            listOf(other.certificate, identified.certificate),
            AT,
        )
        outcome121.isValid shouldBe true
        val lost = identified.issue(HOST, extensions = { authorityKeyIdentifier(utf8("none")) })
        validator(root).validate(lost.certificate, listOf(identified.certificate), AT).isValid shouldBe false
        val impostor = Authority.root()
        val decoy = impostor.issue("ca", isCa = true)
        val decoyLeaf = decoy.issue(HOST)
        val result = validator(root).validate(
            decoyLeaf.certificate,
            listOf(decoy.certificate, identified.certificate),
            AT,
        )
        result.shouldBeInstanceOf<PathValidation.Invalid>().failure shouldBe PathFailure.BadSignature
        val chain = (1..4).fold(listOf(root)) { authorities, index ->
            authorities +
                authorities.last().issue(
                    "ca$index",
                    isCa = true,
                )
        }
        val deep = chain.last().issue(HOST)
        val decoyAnchor = TrustAnchor.of(Authority.root().certificate)
        val anchors = listOf(decoyAnchor, TrustAnchor.of(root.certificate))
        val tight = PathValidator(crypto = crypto, anchors = anchors, limits = X509Limits(maximumPathAttempts = 1))
        val outcome147 = tight.validate(
            deep.certificate,
            chain.drop(1).map { authority -> authority.certificate },
            AT,
        )
        outcome147.isValid shouldBe false
    }

    test("purposes, name constraints and policies have their edge cases") {
        val root = Authority.root()
        val server = ValidationParameters(at = NOW, purpose = KeyPurposes.ServerAuth)
        val allowing = root.issue("allowing", isCa = true, extensions = {
            basicConstraints(isCa = true)
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth))
        })
        val outcome162 = validator(root).validate(
            allowing.issue(HOST).certificate,
            listOf(allowing.certificate),
            server,
        )
        outcome162.isValid shouldBe true
        val plain = root.issue("plain", isCa = true)
        validator(root).validate(plain.issue(HOST).certificate, listOf(plain.certificate), server).isValid shouldBe true
        val everything = root.issue("everything", isCa = true, extensions = {
            basicConstraints(isCa = true)
            nameConstraints(NameConstraints(permitted = listOf(GeneralName.Dns(""), GeneralName.RegisteredId(POLICY))))
        })
        val anyName = everything.issue(
            HOST,
            extensions = { subjectAlternativeNames(listOf(GeneralName.Dns("x.y"), GeneralName.RegisteredId(POLICY))) },
        )
        validator(root).validate(anyName.certificate, listOf(everything.certificate), AT).isValid shouldBe true
        val exact = root.issue("exact", isCa = true, extensions = {
            basicConstraints(isCa = true)
            nameConstraints(
                NameConstraints(permitted = listOf(GeneralName.Email(HOST), GeneralName.Dns(".example.com"))),
            )
        })
        val exactLeaf = exact.issue(
            HOST,
            extensions = { subjectAlternativeNames(listOf(GeneralName.Email("ops@$HOST"), GeneralName.Dns(HOST))) },
        )
        validator(root).validate(exactLeaf.certificate, listOf(exact.certificate), AT).isValid shouldBe true
        val bareDomain = exact.issue(
            HOST,
            extensions = { subjectAlternativeNames(listOf(GeneralName.Dns("example.com"))) },
        )
        validator(root).validate(bareDomain.certificate, listOf(exact.certificate), AT).isValid shouldBe false
        val anonymous = exact.issue(
            HOST,
            subject = distinguishedName { },
            extensions = { subjectAlternativeNames(listOf(GeneralName.Dns(HOST))) },
        )
        validator(root).validate(anonymous.certificate, listOf(exact.certificate), AT).isValid shouldBe true
        val mappingFromAny = root.issue("mapping", isCa = true, extensions = {
            basicConstraints(isCa = true)
            certificatePolicies(listOf(POLICY))
            add(
                Extension(
                    ExtensionIds.PolicyMappings,
                    true,
                    der {
                        sequence {
                            sequence {
                                objectIdentifier(KeyPurposes.AnyPolicy)
                                objectIdentifier(OTHER)
                            }
                        }
                    },
                ),
            )
        })
        failureOf(
            validator(root).validate(mappingFromAny.issue(HOST).certificate, listOf(mappingFromAny.certificate), AT),
        ) shouldBe PathFailure.Policy
        val inhibiting = root.issue("inhibiting", isCa = true, extensions = {
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
                                objectIdentifier(OTHER)
                            }
                        }
                    },
                ),
            )
            policyConstraints(PolicyConstraints(requireExplicitPolicy = 1, inhibitPolicyMapping = 0))
        })
        val mappedLeaf = inhibiting.issue(HOST, extensions = {
            certificatePolicies(listOf(OTHER))
            policyConstraints(PolicyConstraints(requireExplicitPolicy = 1))
        })
        val result = validator(root).validate(mappedLeaf.certificate, listOf(inhibiting.certificate), AT)
        result.isValid shouldBe true
        val specific = ValidationParameters(at = NOW, initialPolicies = setOf(POLICY))
        val anyLeaf = root.issue("anyCa", isCa = true, extensions = {
            basicConstraints(isCa = true)
            certificatePolicies(listOf(KeyPurposes.AnyPolicy))
        })
        val anyPolicies = anyLeaf.issue(HOST, extensions = { certificatePolicies(listOf(KeyPurposes.AnyPolicy)) })
        val anyResult = validator(root).validate(anyPolicies.certificate, listOf(anyLeaf.certificate), specific)
        anyResult.shouldBeInstanceOf<PathValidation.Valid>().policies shouldBe setOf(POLICY)
        val noSign = root.issue("crl only", isCa = true, extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign))
        })
        val anchor = TrustAnchor.of(root.certificate)
        CrlRevocationChecker(revocationLists) { _ -> emptyList() }
            .check(
                certificate = noSign.issue(HOST).certificate,
                issuer = noSign.certificate,
                anchor = anchor,
                at = NOW,
            ) shouldBe RevocationStatus.Unknown
    }
})
