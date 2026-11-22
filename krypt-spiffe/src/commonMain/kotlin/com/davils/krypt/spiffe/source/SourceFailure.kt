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

/**
 * Why an [X509Source] refused an update and kept its current material.
 *
 * @since 1.0.0
 */
public enum class SourceFailure {
    /**
     * The update holds no SVID.
     *
     * @since 1.0.0
     */
    NoSvid,

    /**
     * The update holds more SVIDs or trust domains than the limits allow.
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * The bundles lack the bundle of the trust domain of an SVID.
     *
     * @since 1.0.0
     */
    MissingBundle,

    /**
     * A bundle has a lower `spiffe_sequence` than the bundle of its trust domain the source holds, as a replay of an
     * old bundle would.
     *
     * @since 1.0.0
     */
    Rollback,
}
