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

package com.davils.krypt.keystore.material

import kotlinx.io.bytestring.ByteString

/**
 * Writes key material for krypt, which never opens a file itself; the application implements it over its file
 * system, a secret store or a vault.
 *
 * @since 1.0.0
 */
public fun interface MaterialSink {
    /**
     * Writes [bytes] under [ref], replacing what was there.
     *
     * A sink writes atomically, so a reader sees the old or the new material, never a part, and restricts access to
     * secret material before the first byte is written, for example by creating a file with the permissions of its
     * owner only. Exceptions are not caught by krypt.
     *
     * @param ref the reference.
     * @param bytes the material.
     * @param isSecret whether the material holds a private key, even an encrypted one.
     * @since 1.0.0
     */
    public suspend fun write(ref: MaterialRef, bytes: ByteString, isSecret: Boolean)
}
