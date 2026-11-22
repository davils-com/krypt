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
 * Whether a server asks its clients for a certificate.
 *
 * @since 1.0.0
 */
public enum class ClientAuthentication {
    /**
     * The server asks for no certificate.
     *
     * @since 1.0.0
     */
    None,

    /**
     * The server asks for a certificate and accepts a client without one; a certificate the client sends must be valid.
     *
     * @since 1.0.0
     */
    Requested,

    /**
     * The server refuses a client without a valid certificate.
     *
     * @since 1.0.0
     */
    Required,
}
