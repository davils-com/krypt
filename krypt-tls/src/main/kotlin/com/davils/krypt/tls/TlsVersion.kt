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

package com.davils.krypt.tls

/**
 * A version of TLS that krypt negotiates.
 *
 * @property protocolName the name of the version in JSSE.
 * @since 1.0.0
 */
public enum class TlsVersion(public val protocolName: String) {
    /**
     * TLS 1.3 of RFC 8446, the default.
     *
     * @since 1.0.0
     */
    Tls13("TLSv1.3"),

    /**
     * TLS 1.2 of RFC 5246, only with forward secret AEAD cipher suites and only by opt-in.
     *
     * @since 1.0.0
     */
    Tls12("TLSv1.2"),
}
