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

package com.davils.krypt.keyset.internal

import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.key.PublicKey

internal object KeyTypes {
    val SIGNING: Set<KeyType> = setOf(
        KeyType.Ed25519,
        KeyType.Ed448,
        KeyType.P256,
        KeyType.P384,
        KeyType.P521,
        KeyType.Rsa2048,
        KeyType.Rsa3072,
        KeyType.Rsa4096,
        KeyType.MlDsa44,
        KeyType.MlDsa65,
        KeyType.MlDsa87,
    )

    private val KEMS: Map<KemAlgorithm, KeyType> = mapOf(
        KemAlgorithm.DhkemX25519 to KeyType.X25519,
        KemAlgorithm.DhkemP256 to KeyType.P256,
        KemAlgorithm.DhkemP384 to KeyType.P384,
        KemAlgorithm.DhkemP521 to KeyType.P521,
        KemAlgorithm.MlKem768 to KeyType.MlKem768,
        KemAlgorithm.MlKem1024 to KeyType.MlKem1024,
    )

    fun ofKem(kem: KemAlgorithm): KeyType = KEMS.getValue(kem)

    fun matches(type: KeyType, key: PublicKey): Boolean = matches(
        type = type,
        family = key.family,
        bits = key.bits,
        curve = key.curve,
    )

    fun matches(type: KeyType, family: Any, bits: Int, curve: Any?): Boolean =
        listOf(type.family, type.bits, type.curve) == listOf(family, bits, curve)
}
