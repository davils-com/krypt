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

package com.davils.krypt.spiffe.source

import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.TrustBundle

/**
 * Supplies the trust bundle of a trust domain, such as from the Workload API, a bundle endpoint of SPIFFE federation
 * or configuration. krypt opens no socket and speaks no gRPC: the application implements this interface over the
 * transport it chose; [X509Source] and [com.davils.krypt.spiffe.bundle.BundleSet] are implementations that hold
 * bundles in memory.
 *
 * The validators of krypt ask only for the bundle of the trust domain of the SPIFFE id they validate, as the SPIFFE
 * Federation specification demands, and never merge bundles. A source that fails is contained and counts as a
 * missing bundle.
 *
 * @since 1.0.0
 */
public fun interface BundleSource {
    /**
     * Returns the current bundle of [trustDomain].
     *
     * @param trustDomain the trust domain.
     * @return the bundle, or null if the trust domain is unknown.
     * @since 1.0.0
     */
    public suspend fun bundle(trustDomain: TrustDomain): TrustBundle?
}
