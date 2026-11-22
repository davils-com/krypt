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

package com.davils.krypt.authority.profile

/**
 * A rule of a profile beyond its key usages and purposes.
 *
 * @since 1.0.0
 */
public enum class ProfileRule {
    /**
     * An RSA key also gets the key usage keyEncipherment, which TLS 1.2 with RSA key transport and S/MIME need;
     * other keys never get it.
     *
     * @since 1.0.0
     */
    RsaKeyEncipherment,

    /**
     * The extended key usage is critical, as RFC 3161 demands of a time-stamping authority.
     *
     * @since 1.0.0
     */
    CriticalPurposes,

    /**
     * The certificate names exactly one URI and nothing else, as a SPIFFE X.509-SVID does.
     *
     * @since 1.0.0
     */
    SingleUri,

    /**
     * The certificate demands a stapled OCSP response through the TLS feature extension (RFC 7633).
     *
     * @since 1.0.0
     */
    MustStaple,

    /**
     * The certificate carries ocsp-nocheck, as a delegated OCSP responder does.
     *
     * @since 1.0.0
     */
    OcspNoCheck,
}
