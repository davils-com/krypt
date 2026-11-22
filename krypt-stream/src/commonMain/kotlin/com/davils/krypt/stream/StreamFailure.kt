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

package com.davils.krypt.stream

/**
 * Why a container could not be read.
 *
 * @since 1.0.0
 */
public enum class StreamFailure {
    /**
     * The bytes are not a container of krypt, or they break a limit.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The container names a version or a suite krypt does not know, or a suite the platform lacks, such as
     * ChaCha20-Poly1305 on WebAssembly.
     *
     * @since 1.0.0
     */
    Unsupported,

    /**
     * No credential opened a recipient of the container.
     *
     * @since 1.0.0
     */
    NotARecipient,

    /**
     * The crypto policy forbids the suite of the container or what a recipient needs, such as the iterations of a
     * password.
     *
     * @since 1.0.0
     */
    Refused,

    /**
     * The container was changed, truncated, extended or reordered, or the associated data differs; the plaintext
     * written so far must be discarded.
     *
     * @since 1.0.0
     */
    DecryptionFailed,
}
