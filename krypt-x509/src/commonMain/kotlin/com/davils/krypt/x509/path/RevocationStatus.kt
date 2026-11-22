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

package com.davils.krypt.x509.path

/**
 * The revocation status of a certificate.
 *
 * @since 1.0.0
 */
public enum class RevocationStatus {
    /**
     * The certificate is not revoked, by a fresh and authentic answer.
     *
     * @since 1.0.0
     */
    Good,

    /**
     * The certificate is revoked.
     *
     * @since 1.0.0
     */
    Revoked,

    /**
     * No fresh and authentic answer is known.
     *
     * @since 1.0.0
     */
    Unknown,
}
