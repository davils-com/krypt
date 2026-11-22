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

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.extension.DistributionPoint
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.revocationLists
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.TimeSource

private const val AUDIT_HOST: String = "api.example.com"
private const val POOL: Int = 6
private const val GARBAGE_POOL: Int = 7
private const val GARBAGE_BUDGET_MILLIS: Long = 1_500L
private val AUDIT_POLICY: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.1")
private val AUDIT_OTHER: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.2")
private val AUDIT_UNKNOWN: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.9")
private val AUDIT_AT: ValidationParameters = ValidationParameters(at = NOW)

private fun anchored(root: Authority, revocation: RevocationChecker? = null): PathValidator =
    PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(root.certificate)), revocation = revocation)

class AuditPathTest : FunSpec({
    test("path building stops after maximumPathAttempts checks") {
        val root = Authority.root()
        val pool = (1..POOL).map { root.issue("Root", isCa = true).certificate }
        val attacker = Authority.root()
        val leaf = attacker.issue(AUDIT_HOST).certificate
        var checks = 0
        val counting = RevocationChecker { _, _, _, _ ->
            checks += 1
            RevocationStatus.Good
        }
        val result = anchored(root, counting).validate(leaf, pool, AUDIT_AT)
        result.isValid shouldBe false
        checks shouldBeLessThanOrEqual X509Limits.DEFAULT_MAXIMUM_PATH_ATTEMPTS + 1
    }

    test("forged self-issued intermediates do not make path building exponential") {
        val root = Authority.root()
        val attacker = Authority.root()
        val pool = (1..GARBAGE_POOL).map { attacker.issue("Root", isCa = true).certificate }
        val leaf = attacker.issue(AUDIT_HOST).certificate
        val start = TimeSource.Monotonic.markNow()
        val result = anchored(root).validate(leaf, pool, AUDIT_AT)
        val elapsed = start.elapsedNow().inWholeMilliseconds
        println("audit: $GARBAGE_POOL forged intermediates took $elapsed ms")
        result.isValid shouldBe false
        elapsed shouldBeLessThan GARBAGE_BUDGET_MILLIS
    }

    test("a partition of a revocation list does not vouch for a certificate of another partition") {
        val root = Authority.root()
        val pointA = GeneralName.Uri("http://crl.example.com/a.crl")
        val pointB = GeneralName.Uri("http://crl.example.com/b.crl")
        val leaf = root.issue(AUDIT_HOST, extensions = {
            basicConstraints(isCa = false)
            keyUsage(setOf(KeyUsage.DigitalSignature))
            crlDistributionPoints(listOf(DistributionPoint(listOf(pointB))))
        }).certificate
        val partitionB = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW - 2.hours
            nextUpdate = NOW + 1.days
            number = DerInteger.of(1L)
            issuingDistributionPoint = IssuingDistributionPoint(names = listOf(pointB))
            revoke(leaf.serialNumber, NOW - 3.hours)
        }
        val partitionA = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW - 1.hours
            nextUpdate = NOW + 1.days
            number = DerInteger.of(2L)
            issuingDistributionPoint = IssuingDistributionPoint(names = listOf(pointA))
        }
        val anchor = TrustAnchor.of(root.certificate)
        val onlyA = CrlRevocationChecker(revocationLists) { _ -> listOf(partitionA) }
        onlyA.check(certificate = leaf, issuer = null, anchor = anchor, at = NOW) shouldNotBe RevocationStatus.Good
        val both = CrlRevocationChecker(revocationLists) { _ -> listOf(partitionA, partitionB) }
        both.check(certificate = leaf, issuer = null, anchor = anchor, at = NOW) shouldBe RevocationStatus.Revoked
        anchored(root, both).validate(leaf, parameters = AUDIT_AT).isValid shouldBe false
    }

    test("a revocation list with an unknown critical extension is not used") {
        val root = Authority.root()
        val leaf = root.issue(AUDIT_HOST).certificate
        val list = revocationLists.issue(root.signer) {
            issuer = root.certificate.subject
            thisUpdate = NOW - 1.hours
            nextUpdate = NOW + 1.days
            number = DerInteger.of(1L)
            extensions { add(Extension(AUDIT_UNKNOWN, true, der { nullValue() })) }
        }
        val checker = CrlRevocationChecker(revocationLists) { _ -> listOf(list) }
        val anchor = TrustAnchor.of(root.certificate)
        checker.check(certificate = leaf, issuer = null, anchor = anchor, at = NOW) shouldBe RevocationStatus.Unknown
    }

    test("a wildcard does not carry a certificate into an excluded subtree") {
        val root = Authority.root()
        val constrained = root.issue("constrained", isCa = true, extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign))
            nameConstraints(NameConstraints(excluded = listOf(GeneralName.Dns("secret.example.com"))))
        })
        val wildcard = constrained.issue(AUDIT_HOST, extensions = {
            basicConstraints(isCa = false)
            subjectAlternativeNames(listOf(GeneralName.Dns("*.example.com")))
        }).certificate
        val result = anchored(root).validate(wildcard, listOf(constrained.certificate), AUDIT_AT)
        val isAccepted = result.isValid && ServiceIdentity.matches(wildcard, "secret.example.com")
        isAccepted shouldBe false
    }

    test("a URI with a trailing dot stays in its excluded subtree") {
        val root = Authority.root()
        val constrained = root.issue("constrained", isCa = true, extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign))
            nameConstraints(NameConstraints(excluded = listOf(GeneralName.Uri("evil.com"))))
        })
        val dotted = constrained.issue(AUDIT_HOST, extensions = {
            basicConstraints(isCa = false)
            subjectAlternativeNames(listOf(GeneralName.Uri("https://evil.com./login")))
        }).certificate
        anchored(root).validate(dotted, listOf(constrained.certificate), AUDIT_AT).isValid shouldBe false
    }

    test("a user policy is compared in the domain of the anchor, as the policy tree of RFC 5280 does") {
        val root = Authority.root()
        val mapping = root.issue("mapping", isCa = true, extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign))
            certificatePolicies(listOf(AUDIT_POLICY))
            add(
                Extension(
                    ExtensionIds.PolicyMappings,
                    true,
                    der {
                        sequence {
                            sequence {
                                objectIdentifier(AUDIT_POLICY)
                                objectIdentifier(AUDIT_OTHER)
                            }
                        }
                    },
                ),
            )
        })
        val leaf = mapping.issue(AUDIT_HOST, extensions = {
            basicConstraints(isCa = false)
            certificatePolicies(listOf(AUDIT_OTHER))
        }).certificate
        val parameters = ValidationParameters(
            at = NOW,
            initialPolicies = setOf(AUDIT_OTHER),
            isExplicitPolicyRequired = true,
        )
        val result = anchored(root).validate(leaf, listOf(mapping.certificate), parameters)
        (result as? PathValidation.Invalid)?.failure shouldBe PathFailure.Policy
    }

    test("a trust anchor presented as the end entity is still checked for validity and purpose") {
        val root = Authority.root(extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.DigitalSignature))
            extendedKeyUsage(listOf(KeyPurposes.ClientAuth))
        })
        val later = ValidationParameters(at = NOW + 400.days, purpose = KeyPurposes.ServerAuth)
        anchored(root).validate(root.certificate, parameters = later).isValid shouldBe false
    }
})
