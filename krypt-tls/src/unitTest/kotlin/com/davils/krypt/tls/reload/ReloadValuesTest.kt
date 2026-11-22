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

package com.davils.krypt.tls.reload

import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.keystore.material.MaterialFailure
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

private const val TEXT: String = "text"

class ReloadValuesTest : FunSpec({
    test("reload settings are bounded and compare by value") {
        val settings = ReloadSettings()
        settings shouldBe ReloadSettings()
        settings.hashCode() shouldBe ReloadSettings().hashCode()
        (settings == ReloadSettings(debounce = 1.seconds)) shouldBe false
        settings.equals(TEXT) shouldBe false
        settings.toString() shouldContain "holdDown"
        shouldThrow<IllegalArgumentException> { ReloadSettings(debounce = (-1).seconds) }
        shouldThrow<IllegalArgumentException> { ReloadSettings(holdDown = 2.hours) }
        shouldThrow<IllegalArgumentException> { ReloadSettings(expiryWarning = (-1).seconds) }
        shouldThrow<IllegalArgumentException> { ReloadSettings(expiryWarning = 400.days) }
    }

    test("reload events compare by value and name no material") {
        val event = ReloadEvent(ReloadAction.Failed, 2L, MaterialFailure.Missing)
        event shouldBe ReloadEvent(ReloadAction.Failed, 2L, MaterialFailure.Missing)
        event.hashCode() shouldBe ReloadEvent(ReloadAction.Failed, 2L, MaterialFailure.Missing).hashCode()
        (event == ReloadEvent(ReloadAction.Reloaded, 2L, null)) shouldBe false
        event.equals(TEXT) shouldBe false
        event.component shouldBe "tls"
        event.toString() shouldContain "Missing"
        ReloadEvent(ReloadAction.Reloaded, 1L, null).toString() shouldContain "none"
    }

    test("the expiry of a certificate is judged at a time against a warning") {
        val pki = Pki.create()
        val certificate = pki.identity(CertificateProfile.TlsServer, SERVER_NAME).certificate
        val inside = certificate.notBefore + 1.hours
        CertificateExpiry.of(certificate, certificate.notBefore - 1.hours, 1.days).state shouldBe
            ExpiryState.NotYetValid
        CertificateExpiry.of(certificate, inside, 1.days).state shouldBe ExpiryState.Valid
        CertificateExpiry.of(certificate, certificate.notAfter - 1.hours, 1.days).state shouldBe ExpiryState.Expiring
        CertificateExpiry.of(certificate, certificate.notAfter + 1.hours, 1.days).state shouldBe ExpiryState.Expired
        val expiry = CertificateExpiry.of(certificate, inside, 1.days)
        expiry shouldBe CertificateExpiry.of(certificate, inside, 1.days)
        expiry.hashCode() shouldBe CertificateExpiry.of(certificate, inside, 1.days).hashCode()
        (expiry == CertificateExpiry.of(certificate, inside + 1.hours, 1.days)) shouldBe false
        expiry.equals(TEXT) shouldBe false
        expiry.remaining shouldBe certificate.notAfter - inside
        expiry.toString() shouldContain "Valid"
    }
})
