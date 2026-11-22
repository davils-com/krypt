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

/**
 * How the revocation of the certificates of a peer is checked.
 *
 * @since 1.0.0
 */
public enum class RevocationMode {
    /**
     * No revocation is checked, and no TLS feature extension is enforced.
     *
     * @since 1.0.0
     */
    Off,

    /**
     * A revoked certificate is refused; a certificate of unknown status is accepted.
     *
     * @since 1.0.0
     */
    SoftFail,

    /**
     * A revoked certificate and a certificate of unknown status are refused.
     *
     * @since 1.0.0
     */
    HardFail,
}
