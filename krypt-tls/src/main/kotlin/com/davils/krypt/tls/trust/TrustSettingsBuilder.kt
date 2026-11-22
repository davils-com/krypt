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

package com.davils.krypt.tls.trust

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.ct.CtPolicy
import com.davils.krypt.ct.LogList
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.path.PinSet
import com.davils.krypt.x509.path.RevocationListSource
import com.davils.krypt.x509.path.TrustAnchor

/**
 * Builds [TrustSettings]: no anchors, no system anchors, soft-fail revocation and enforced must-staple by default.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class TrustSettingsBuilder internal constructor() : ValidatingBuilder<TrustSettings>() {
    override val subject: String get() = "trust"

    /**
     * See [TrustSettings.anchors].
     *
     * @since 1.0.0
     */
    public var anchors: List<TrustAnchor> = emptyList()
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.isSystemIncluded].
     *
     * @since 1.0.0
     */
    public var isSystemIncluded: Boolean = false
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.pins].
     *
     * @since 1.0.0
     */
    public var pins: PinSet? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.revocation].
     *
     * @since 1.0.0
     */
    public var revocation: RevocationMode = RevocationMode.SoftFail
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.ocspSource].
     *
     * @since 1.0.0
     */
    public var ocspSource: OcspResponseSource? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.revocationListSource].
     *
     * @since 1.0.0
     */
    public var revocationListSource: RevocationListSource? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.cache].
     *
     * @since 1.0.0
     */
    public var cache: RevocationCache? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.isMustStapleEnforced].
     *
     * @since 1.0.0
     */
    public var isMustStapleEnforced: Boolean = true
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.transparency].
     *
     * @since 1.0.0
     */
    public var transparency: TransparencyRequirement? = null
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [TrustSettings.limits].
     *
     * @since 1.0.0
     */
    public var limits: X509Limits = X509Limits.Default
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Requires the timestamps of [logs] to satisfy [policy].
     *
     * @param logs the logs the application trusts.
     * @param policy the CT policy.
     * @since 1.0.0
     */
    public fun transparency(logs: LogList, policy: CtPolicy = CtPolicy.Default) {
        transparency = TransparencyRequirement(logs, policy)
    }

    override fun assemble(): TrustSettings = TrustSettings(this)
}
