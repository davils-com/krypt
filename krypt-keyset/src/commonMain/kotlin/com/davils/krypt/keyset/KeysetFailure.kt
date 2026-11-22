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

package com.davils.krypt.keyset

/**
 * Why a key set could not be read.
 *
 * @since 1.0.0
 */
public enum class KeysetFailure {
    /**
     * The encoding is not a key set of krypt, breaks a limit or contradicts itself.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The key set names an algorithm, a key type or a version krypt does not know.
     *
     * @since 1.0.0
     */
    Unsupported,

    /**
     * The crypto policy forbids a key of the key set.
     *
     * @since 1.0.0
     */
    Refused,

    /**
     * The key set was encrypted by another key management service.
     *
     * @since 1.0.0
     */
    WrongKeyManagementService,

    /**
     * The key management service could not decrypt the key set: the key set or its associated data was changed, or
     * it was encrypted with another key.
     *
     * @since 1.0.0
     */
    DecryptionFailed,

    /**
     * No key set is stored under the name.
     *
     * @since 1.0.0
     */
    Missing,

    /**
     * Another key set is stored under the name, or other processes kept changing it.
     *
     * @since 1.0.0
     */
    Conflict,
}
