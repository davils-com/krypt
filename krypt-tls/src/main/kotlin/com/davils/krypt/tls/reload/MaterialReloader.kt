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

@file:OptIn(DavilsInternal::class, ExperimentalAtomicApi::class)

package com.davils.krypt.tls.reload

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.telemetry.EventSink
import com.davils.krypt.keystore.Identity
import com.davils.krypt.keystore.material.IdentitySpec
import com.davils.krypt.keystore.material.MaterialFailure
import com.davils.krypt.keystore.material.MaterialLoader
import com.davils.krypt.keystore.material.MaterialRef
import com.davils.krypt.tls.TlsConfiguration
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.trust.TrustSettings
import com.davils.krypt.x509.path.TrustAnchor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Instant

/**
 * Reloads the identities and anchors of a [TlsContext] through a [MaterialLoader] of krypt-keystore, when the
 * application calls [reload] or a change arrives on the flow it hands to [watch].
 *
 * A reload loads every identity and every anchor first and swaps them in only if all of them loaded, atomically for
 * every later handshake; if one fails, the last good material stays in use and a [ReloadEvent] with the failure is
 * sent. A source of the application that throws is contained and counts as [MaterialFailure.Unavailable]. Reloads run
 * one at a time.
 *
 * The reloader starts no thread and no timer: [watch] runs on the scope of the application, and its debounce and
 * hold-down wait on that scope's dispatcher, measured against the clock of the environment.
 *
 * Safe to share between threads.
 *
 * @property context the context whose material is reloaded.
 * @property loader the loader of the material.
 * @param identities the identities to load, the default first; empty to keep the identities.
 * @param anchors the bundles of anchors to load; empty to keep the anchors.
 * @property settings the timing of [watch] and the warning of [expiry].
 * @constructor Creates a reloader; nothing is loaded until [reload] or [watch].
 * @throws IllegalArgumentException if both [identities] and [anchors] are empty, or there are more identities than
 *   [TlsConfiguration.HARD_MAXIMUM_IDENTITIES] or bundles than [TrustSettings.HARD_MAXIMUM_ANCHORS].
 * @since 1.0.0
 */
public class MaterialReloader(
    public val context: TlsContext,
    public val loader: MaterialLoader,
    identities: List<IdentitySpec>,
    anchors: List<MaterialRef>,
    public val settings: ReloadSettings = ReloadSettings(),
) {
    /**
     * The identities to load.
     *
     * @since 1.0.0
     */
    public val identities: List<IdentitySpec> = identities.toList()

    /**
     * The bundles of anchors to load.
     *
     * @since 1.0.0
     */
    public val anchors: List<MaterialRef> = anchors.toList()

    private val environment = context.configuration.crypto.environment

    private val sink = EventSink(environment, ReloadEvent.TOPIC)

    private val lock = Mutex()

    private val generations = AtomicLong(0L)

    private val lastReload = AtomicReference<Instant?>(null)

    /**
     * The events of every reload, hot and without replay.
     *
     * @since 1.0.0
     */
    public val events: Flow<ReloadEvent> get() = sink.events

    /**
     * The number of reloads that succeeded; 0 while the material of the configuration is in use.
     *
     * @since 1.0.0
     */
    public val generation: Long get() = generations.load()

    init {
        require(this.identities.isNotEmpty() || this.anchors.isNotEmpty()) { "A reloader loads identities or anchors" }
        require(this.identities.size <= TlsConfiguration.HARD_MAXIMUM_IDENTITIES) {
            "At most ${TlsConfiguration.HARD_MAXIMUM_IDENTITIES} identities are loaded"
        }
        require(this.anchors.size <= TrustSettings.HARD_MAXIMUM_ANCHORS) {
            "At most ${TrustSettings.HARD_MAXIMUM_ANCHORS} bundles of anchors are loaded"
        }
    }

    /**
     * Loads the material and swaps it in, or keeps the last good material if loading fails.
     *
     * @return the new generation, or why loading failed.
     * @since 1.0.0
     */
    public suspend fun reload(): Outcome<Long, MaterialFailure> = lock.withLock {
        val loaded = attempted { load() }.getOrDefault(Outcome.Failure(MaterialFailure.Unavailable))
        when (loaded) {
            is Outcome.Success -> swap(loaded.value)
            is Outcome.Failure -> failed(loaded.failure)
        }
    }

    /**
     * Reloads on every change [changes] emits, once the changes have been quiet for [ReloadSettings.debounce] and at
     * least [ReloadSettings.holdDown] after the last reload. A change that arrives while a reload waits restarts the
     * wait.
     *
     * @param scope the scope of the application, which runs and cancels the watch.
     * @param changes the change signals of the application, such as from a watch of its files.
     * @return the job of the watch.
     * @since 1.0.0
     */
    public fun watch(scope: CoroutineScope, changes: Flow<*>): Job = scope.launch {
        changes.collectLatest {
            delay(settings.debounce)
            holdDown()
            reload()
        }
    }

    /**
     * Returns the expiry status of the certificates of the identities in use, each judged against
     * [ReloadSettings.expiryWarning] at the time of the clock of the environment.
     *
     * @return the status of every identity, the default first.
     * @since 1.0.0
     */
    public fun expiry(): List<CertificateExpiry> {
        val at = environment.clock.now()
        return context.keyManager.identities.map { identity ->
            CertificateExpiry.of(certificate = identity.certificate, at = at, warning = settings.expiryWarning)
        }
    }

    /**
     * Shows what is loaded and the generation.
     *
     * @return the reloader as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "MaterialReloader(identities=${identities.size}, anchors=${anchors.size}, generation=$generation, $settings)"

    private suspend fun load(): Outcome<Material, MaterialFailure> {
        val loadedIdentities = identities.map { spec -> loader.identity(spec) }
        val loadedAnchors = anchors.map { ref -> loader.anchors(ref) }
        val outcomes = loadedIdentities + loadedAnchors
        val failure = outcomes.firstNotNullOfOrNull { outcome -> outcome.failureOrNull() }
        val trusted = loadedAnchors.flatMap { outcome -> outcome.getOrNull().orEmpty() }
        val isBounded = trusted.size <= TrustSettings.HARD_MAXIMUM_ANCHORS
        val refusal = failure ?: MaterialFailure.TooLarge.takeUnless { isBounded }
        val loaded = loadedIdentities.mapNotNull { outcome -> outcome.getOrNull() }
        val material = Material(
            identities = loaded.takeIf { identities.isNotEmpty() },
            anchors = trusted.takeIf { anchors.isNotEmpty() },
        )
        return refusal?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(material)
    }

    private fun swap(material: Material): Outcome<Long, MaterialFailure> {
        context.rotate(identities = material.identities, anchors = material.anchors)
        val generation = generations.addAndFetch(1L)
        lastReload.store(environment.clock.now())
        sink.emit { ReloadEvent(action = ReloadAction.Reloaded, generation = generation, failure = null) }
        return Outcome.Success(generation)
    }

    private fun failed(failure: MaterialFailure): Outcome<Long, MaterialFailure> {
        sink.emit { ReloadEvent(action = ReloadAction.Failed, generation = generation, failure = failure) }
        return Outcome.Failure(failure)
    }

    private suspend fun holdDown() {
        val last = lastReload.load() ?: return
        val wait = last + settings.holdDown - environment.clock.now()
        delay(wait)
    }

    private data class Material(val identities: List<Identity>?, val anchors: List<TrustAnchor>?)
}
