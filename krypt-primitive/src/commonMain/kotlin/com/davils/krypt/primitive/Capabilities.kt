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

package com.davils.krypt.primitive

import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.internal.Backend
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * What the running platform and the configured provider can do, asked once and remembered for this [Crypto].
 *
 * The answer describes the platform, not the policy: an algorithm can be available and still be forbidden. On the
 * JVM it depends on the JDK and the provider; on WebAssembly on the WebCrypto of the host, so a recent Node.js offers
 * more than an older browser. A capability is probed by trying the algorithm, never guessed from a version.
 *
 * @since 1.0.0
 */
public class Capabilities internal constructor(private val backend: Backend) {
    private val lock = Mutex()
    private val algorithms = mutableMapOf<Algorithm, Boolean>()
    private val types = mutableMapOf<KeyType, Boolean>()

    /**
     * Tells whether incremental hashing is available, which WebCrypto lacks; without it a digest needs the whole input
     * at once.
     *
     * @since 1.0.0
     */
    public val hasIncrementalDigest: Boolean = backend.hasIncrementalDigest

    /**
     * Tells whether [algorithm] is available.
     *
     * @param algorithm the algorithm.
     * @return true if the platform can run it.
     * @since 1.0.0
     */
    public suspend fun supports(algorithm: Algorithm): Boolean = lock.withLock {
        algorithms.getOrPut(algorithm) { backend.supports(algorithm) }
    }

    /**
     * Tells whether keys of [type] can be generated and used.
     *
     * @param type the key type.
     * @return true if the platform can generate it.
     * @since 1.0.0
     */
    public suspend fun supports(type: KeyType): Boolean = lock.withLock {
        types.getOrPut(
            type,
        ) { backend.supports(type) }
    }
}
