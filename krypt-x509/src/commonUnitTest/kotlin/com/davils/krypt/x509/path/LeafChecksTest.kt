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

import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days

private const val HOST: String = "api.example.com"
private const val LATER_DAYS: Int = 400

private fun validator(root: Authority): PathValidator =
    PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(root.certificate)))

private fun failureOf(result: PathValidation): PathFailure? = (result as? PathValidation.Invalid)?.failure

private fun serving(): ValidationParameters = ValidationParameters(at = NOW, purpose = KeyPurposes.ServerAuth)

class LeafChecksTest : FunSpec({
    test("a trust anchor presented as the end entity is still checked for validity and purpose") {
        val root = Authority.root(extensions = {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.DigitalSignature))
            extendedKeyUsage(listOf(KeyPurposes.ClientAuth))
        })
        val later = ValidationParameters(at = NOW + LATER_DAYS.days, purpose = KeyPurposes.ServerAuth)
        failureOf(validator(root).validate(root.certificate, parameters = later)) shouldBe PathFailure.Expired
        failureOf(validator(root).validate(root.certificate, parameters = serving())) shouldBe PathFailure.Purpose
        val clients = ValidationParameters(at = NOW, purpose = KeyPurposes.ClientAuth)
        val valid = validator(root).validate(root.certificate, parameters = clients)
        (valid as? PathValidation.Valid)?.path shouldBe listOf(root.certificate)
    }

    test("a trust anchor as the end entity needs the key usage of the purpose") {
        val root = Authority.root()
        failureOf(validator(root).validate(root.certificate, parameters = serving())) shouldBe PathFailure.KeyUsage
    }

    test("the key usage of the end entity must suit the purpose") {
        val root = Authority.root()
        val signing = root.issue(HOST).certificate
        validator(root).validate(signing, parameters = serving()).isValid shouldBe true
        val enciphering = root
            .issue(HOST, extensions = {
                basicConstraints(isCa = false)
                keyUsage(setOf(KeyUsage.KeyEncipherment))
            })
            .certificate
        validator(root).validate(enciphering, parameters = serving()).isValid shouldBe true
        val clients = ValidationParameters(at = NOW, purpose = KeyPurposes.ClientAuth)
        failureOf(validator(root).validate(enciphering, parameters = clients)) shouldBe PathFailure.KeyUsage
        val signer = root
            .issue(HOST, extensions = {
                basicConstraints(isCa = false)
                keyUsage(setOf(KeyUsage.ContentCommitment))
            })
            .certificate
        failureOf(validator(root).validate(signer, parameters = serving())) shouldBe PathFailure.KeyUsage
        val coding = ValidationParameters(at = NOW, purpose = KeyPurposes.CodeSigning)
        validator(root).validate(signer, parameters = coding).isValid shouldBe true
        val unrestricted = root.issue(HOST, extensions = { basicConstraints(isCa = false) }).certificate
        validator(root).validate(unrestricted, parameters = serving()).isValid shouldBe true
    }
})
