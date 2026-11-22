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

import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.TimeSource

private const val HOST: String = "api.example.com"
private const val ROOT_NAME: String = "Root"
private const val INTERMEDIATE: String = "intermediate"
private const val POOL: Int = 6
private const val FORGED_POOL: Int = 12
private const val FORGED_BUDGET_MILLIS: Long = 5_000L
private const val TIGHT_UNITS: Int = 3
private val AT: ValidationParameters = ValidationParameters(at = NOW)

private fun validator(
    root: Authority,
    revocation: RevocationChecker? = null,
    limits: X509Limits = X509Limits.Default,
): PathValidator = PathValidator(
    crypto = crypto,
    anchors = listOf(TrustAnchor.of(root.certificate)),
    revocation = revocation,
    limits = limits,
)

private fun failureOf(result: PathValidation): PathFailure? = (result as? PathValidation.Invalid)?.failure

class PathWorkTest : FunSpec({
    test("path building stops when its units of work are spent") {
        val root = Authority.root()
        val pool = (1..POOL).map { root.issue(ROOT_NAME, isCa = true).certificate }
        val leaf = Authority.root().issue(HOST).certificate
        var checks = 0
        val counting = RevocationChecker { _, _, _, _ ->
            checks += 1
            RevocationStatus.Good
        }
        validator(root, counting).validate(leaf, pool, AT).isValid shouldBe false
        checks shouldBeLessThanOrEqual X509Limits.DEFAULT_MAXIMUM_PATH_ATTEMPTS
    }

    test("forged self-issued intermediates do not make path building exponential") {
        val root = Authority.root()
        val attacker = Authority.root()
        val pool = (1..FORGED_POOL).map { attacker.issue(ROOT_NAME, isCa = true).certificate }
        val leaf = attacker.issue(HOST).certificate
        val start = TimeSource.Monotonic.markNow()
        val result = validator(root).validate(leaf, pool, AT)
        result.isValid shouldBe false
        start.elapsedNow().inWholeMilliseconds shouldBeLessThan FORGED_BUDGET_MILLIS
    }

    test("duplicates count once and too many intermediates are refused") {
        val root = Authority.root()
        val intermediate = root.issue(INTERMEDIATE, isCa = true)
        val leaf = intermediate.issue(HOST).certificate
        val narrow = X509Limits(maximumIntermediates = 1)
        val copies = List(POOL) { intermediate.certificate } + leaf
        validator(root = root, limits = narrow).validate(leaf, copies, AT).isValid shouldBe true
        val other = root.issue(INTERMEDIATE, isCa = true).certificate
        val crowded = validator(
            root = root,
            limits = narrow,
        ).validate(leaf, listOf(intermediate.certificate, other), AT)
        failureOf(crowded) shouldBe PathFailure.PathTooLong
    }

    test("an issuer whose key identifier matches is tried first") {
        val root = Authority.root()
        val identifier = utf8(INTERMEDIATE)
        val anonymous = root.issue(INTERMEDIATE, isCa = true)
        val named = root.issue(INTERMEDIATE, isCa = true, extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign))
            subjectKeyIdentifier(identifier)
        })
        val leaf = named
            .issue(HOST, extensions = {
                basicConstraints(isCa = false)
                authorityKeyIdentifier(identifier)
            })
            .certificate
        val tight = X509Limits(maximumPathAttempts = TIGHT_UNITS)
        val pool = listOf(anonymous.certificate, named.certificate)
        validator(root = root, limits = tight).validate(leaf, pool, AT).isValid shouldBe true
        val reversed = validator(root = root, limits = tight).validate(leaf, pool.reversed(), AT)
        reversed.isValid shouldBe true
    }

    test("a failing revocation checker counts as an unknown status") {
        val root = Authority.root()
        val leaf = root.issue(HOST).certificate
        val failing = RevocationChecker { _, _, _, _ -> error("unreachable responder") }
        failureOf(validator(root, failing).validate(leaf, parameters = AT)) shouldBe PathFailure.RevocationUnknown
        val lenient = ValidationParameters(at = NOW, isRevocationRequired = false)
        validator(root, failing).validate(leaf, parameters = lenient).isValid shouldBe true
    }

    test("the limits of path building have hard ceilings") {
        val limits = X509Limits(maximumIntermediates = 2, maximumPolicyNodes = 2)
        limits shouldBe X509Limits(maximumIntermediates = 2, maximumPolicyNodes = 2)
        limits.toString() shouldContain "maximumIntermediates=2"
        limits shouldBe limits
        (limits == X509Limits(maximumIntermediates = 2)) shouldBe false
        shouldThrow<IllegalArgumentException> { X509Limits(maximumIntermediates = 0) }
        shouldThrow<IllegalArgumentException> {
            X509Limits(maximumIntermediates = X509Limits.HARD_MAXIMUM_INTERMEDIATES + 1)
        }
        shouldThrow<IllegalArgumentException> { X509Limits(maximumPolicyNodes = 0) }
        shouldThrow<IllegalArgumentException> {
            X509Limits(maximumPolicyNodes = X509Limits.HARD_MAXIMUM_POLICY_NODES + 1)
        }
    }
})
