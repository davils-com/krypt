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

@file:JvmName("JcaInterop")

package com.davils.krypt.primitive

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.RandomSource
import com.davils.krypt.core.provider
import com.davils.krypt.primitive.internal.JcaInstances
import com.davils.krypt.primitive.internal.RandomSourceAdapter
import com.davils.krypt.primitive.key.PrivateKey
import java.security.SecureRandom
import java.security.PrivateKey as JcaPrivateKey

/**
 * Returns the JCA key behind [key], for an API of the JDK that signs with it itself, such as the key manager of JSSE.
 *
 * The key is opened through the provider of the environment; a key held by a provider, such as one in a hardware
 * security module, is returned as the handle it is, never extracted.
 *
 * @receiver the crypto object whose environment names the provider of [key].
 * @param key the private key.
 * @return the JCA key.
 * @throws IllegalStateException if [key] was destroyed, or has no encoding and a handle that is no JCA key.
 * @since 1.0.0
 */
@DavilsInternal
public fun Crypto.jcaPrivateKey(key: PrivateKey): JcaPrivateKey = JcaInstances(environment.provider).privateKey(key)

/**
 * Returns the randomness of the environment as a [SecureRandom], for an API of the JDK that draws its own, such as an
 * SSLContext: the secure randomness of the platform when the environment uses it, an adapter of its
 * [RandomSource] otherwise.
 *
 * @receiver the crypto object whose environment provides the randomness.
 * @return the randomness.
 * @since 1.0.0
 */
@DavilsInternal
public fun Crypto.secureRandom(): SecureRandom {
    val source = environment.random
    val isPlatform = source === RandomSource.Secure
    return SecureRandom().takeIf { isPlatform } ?: RandomSourceAdapter(source)
}
