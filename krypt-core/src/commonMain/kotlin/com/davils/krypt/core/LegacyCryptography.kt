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

package com.davils.krypt.core

/**
 * Marks an algorithm or a function that is broken or weak and exists only to read what old systems wrote, such as
 * SHA-1 in old certificates, RSA PKCS #1 v1.5 encryption, PBES1 or 3DES in an old PKCS #12 file.
 *
 * Using it is an error until the caller opts in with `@OptIn(LegacyCryptography::class)`, which documents the
 * decision at the call. Even then the [com.davils.krypt.core.policy.CryptoPolicy] of the environment decides whether
 * an operation may use it: no profile of krypt permits a legacy algorithm for anything new.
 *
 * @since 1.0.0
 */
@RequiresOptIn(
    message = "This is legacy cryptography: use it only to read data that old systems wrote, never for new data.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
    AnnotationTarget.TYPEALIAS,
)
public annotation class LegacyCryptography
