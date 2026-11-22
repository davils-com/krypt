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

/**
 * Thrown when the platform or the configured JCA provider does not offer an algorithm, such as Ed448 on WebAssembly
 * or ML-KEM on a JDK before 24. [Capabilities] answers ahead of time which algorithms are available.
 *
 * @property algorithmName the canonical name of the algorithm.
 * @param cause the failure of the platform, if any.
 * @since 1.0.0
 */
public class UnsupportedAlgorithmException(public val algorithmName: String, cause: Throwable? = null) :
    CryptoException("The algorithm $algorithmName is not available on this platform or provider", cause)
