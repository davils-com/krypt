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

@file:OptIn(ExperimentalCoroutinesApi::class)

package com.davils.krypt.tls.reload

import com.davils.kollect.core.health.Health
import com.davils.kollect.core.health.ReasonCode
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.environment
import com.davils.krypt.keystore.material.IdentitySpec
import com.davils.krypt.keystore.material.MaterialFailure
import com.davils.krypt.keystore.material.MaterialLoader
import com.davils.krypt.keystore.material.MaterialRef
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.TlsConfiguration
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.MemorySource
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.tls
import com.davils.krypt.tls.trust.TrustSettings
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val IDENTITY_SPEC: IdentitySpec = IdentitySpec.PemBundle(
    certificates = MaterialRef(MemorySource.CERTIFICATE),
    key = MaterialRef(MemorySource.KEY),
)

private val ANCHOR_REF: MaterialRef = MaterialRef(MemorySource.ANCHORS)

private fun reloaderOf(
    context: TlsContext,
    loader: MaterialLoader,
    identities: List<IdentitySpec>,
    anchors: List<MaterialRef>,
): MaterialReloader = MaterialReloader(context = context, loader = loader, identities = identities, anchors = anchors)

class ReloadTest : FunSpec({
    test("a reload swaps the material in, and a failed one keeps the last good version") {
        val pki = Pki.create()
        val first = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val second = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val context = TlsContext(serverConfiguration(pki, listOf(first)))
        val source = MemorySource()
        source.put(second)
        source.put(pki.certificate)
        val reloader = MaterialReloader(
            context = context,
            loader = MaterialLoader(crypto, source),
            identities = listOf(IDENTITY_SPEC),
            anchors = listOf(ANCHOR_REF),
        )
        val events = async(start = CoroutineStart.UNDISPATCHED) { reloader.events.take(4).toList() }
        reloader.generation shouldBe 0L
        reloader.reload() shouldBe Outcome.Success(1L)
        context.keyManager.identities shouldBe listOf(second)
        context.trustManager.anchors shouldBe listOf(pki.anchor)
        source.remove(MemorySource.KEY)
        reloader.reload() shouldBe Outcome.Failure(MaterialFailure.Missing)
        source.put(second)
        source.remove(MemorySource.ANCHORS)
        reloader.reload() shouldBe Outcome.Failure(MaterialFailure.Missing)
        source.isBroken = true
        reloader.reload() shouldBe Outcome.Failure(MaterialFailure.Unavailable)
        reloader.generation shouldBe 1L
        context.keyManager.identities shouldBe listOf(second)
        events.await().map { event -> event.action to event.failure } shouldBe listOf(
            ReloadAction.Reloaded to null,
            ReloadAction.Failed to MaterialFailure.Missing,
            ReloadAction.Failed to MaterialFailure.Missing,
            ReloadAction.Failed to MaterialFailure.Unavailable,
        )
        reloader.toString() shouldContain "generation=1"
    }

    test("anchors alone are reloaded and too many anchors are refused") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val context = TlsContext(serverConfiguration(pki, listOf(identity)))
        val source = MemorySource()
        source.put(pki.certificate, Pki.create("Other").certificate)
        val reloader = MaterialReloader(
            context = context,
            loader = MaterialLoader(crypto, source),
            identities = emptyList(),
            anchors = listOf(ANCHOR_REF),
        )
        reloader.reload() shouldBe Outcome.Success(1L)
        context.keyManager.identities shouldBe listOf(identity)
        context.trustManager.anchors.size shouldBe 2
        val crowded = MaterialReloader(
            context = context,
            loader = MaterialLoader(crypto, source),
            identities = emptyList(),
            anchors = List(TrustSettings.HARD_MAXIMUM_ANCHORS / 2 + 1) { ANCHOR_REF },
        )
        crowded.reload() shouldBe Outcome.Failure(MaterialFailure.TooLarge)
    }

    test("a reloader needs something to load within the bounds") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val context = TlsContext(serverConfiguration(pki, listOf(identity)))
        val loader = MaterialLoader(crypto, MemorySource())
        val specs = List(TlsConfiguration.HARD_MAXIMUM_IDENTITIES + 1) { IDENTITY_SPEC }
        val refs = List(TrustSettings.HARD_MAXIMUM_ANCHORS + 1) { ANCHOR_REF }
        shouldThrow<IllegalArgumentException> {
            reloaderOf(context = context, loader = loader, identities = emptyList(), anchors = emptyList())
        }
        shouldThrow<IllegalArgumentException> {
            reloaderOf(context = context, loader = loader, identities = specs, anchors = emptyList())
        }
        shouldThrow<IllegalArgumentException> {
            reloaderOf(context = context, loader = loader, identities = emptyList(), anchors = refs)
        }
    }

    test("changes reload after the debounce and not before the hold-down") {
        val pki = Pki.create()
        val first = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val second = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        runTest {
            val start = Instant.fromEpochSeconds(1_700_000_000L)
            val clock = object : Clock {
                override fun now(): Instant = start + testScheduler.currentTime.milliseconds
            }
            val timed = Crypto(environment { this.clock = clock })
            val configuration = tls(TlsRole.Server, timed) {
                identities = listOf(first)
                trust { anchors = listOf(pki.anchor) }
            }
            val context = TlsContext(configuration)
            val source = MemorySource()
            source.put(second)
            val reloader = MaterialReloader(
                context = context,
                loader = MaterialLoader(timed, source),
                identities = listOf(IDENTITY_SPEC),
                anchors = emptyList(),
                settings = ReloadSettings(debounce = 1.seconds, holdDown = 10.seconds),
            )
            val changes = MutableSharedFlow<Unit>()
            val watch = reloader.watch(backgroundScope, changes)
            testScheduler.runCurrent()
            changes.emit(Unit)
            testScheduler.advanceTimeBy(500.milliseconds)
            changes.emit(Unit)
            testScheduler.advanceTimeBy(900.milliseconds)
            reloader.generation shouldBe 0L
            testScheduler.advanceTimeBy(200.milliseconds)
            reloader.generation shouldBe 1L
            changes.emit(Unit)
            testScheduler.advanceTimeBy(2.seconds)
            reloader.generation shouldBe 1L
            testScheduler.advanceTimeBy(9.seconds)
            reloader.generation shouldBe 2L
            reloader.expiry().map { expiry -> expiry.state } shouldBe listOf(ExpiryState.NotYetValid)
            reloader.check() shouldBe Health.down(ReasonCode.StateMatched)
            watch.cancel()
        }
    }

    test("the expiry of the identities in use is reported against the warning") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val context = TlsContext(serverConfiguration(pki, listOf(identity)))
        val loader = MaterialLoader(crypto, MemorySource())
        val relaxed = MaterialReloader(
            context = context,
            loader = loader,
            identities = listOf(IDENTITY_SPEC),
            anchors = emptyList(),
            settings = ReloadSettings(expiryWarning = 1.days),
        )
        relaxed.expiry().single().state shouldBe ExpiryState.Valid
        relaxed.check() shouldBe Health.Up
        val wary = MaterialReloader(
            context = context,
            loader = loader,
            identities = listOf(IDENTITY_SPEC),
            anchors = emptyList(),
            settings = ReloadSettings(expiryWarning = 60.days),
        )
        val expiry = wary.expiry().single()
        expiry.state shouldBe ExpiryState.Expiring
        expiry.certificate shouldBe identity.certificate
        wary.check() shouldBe Health.degraded(ReasonCode.ThresholdCrossed)
    }
})
