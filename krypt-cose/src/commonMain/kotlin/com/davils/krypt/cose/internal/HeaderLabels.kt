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

package com.davils.krypt.cose.internal

import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem

internal object HeaderLabels {
    const val ALGORITHM: Long = 1
    const val CRITICAL: Long = 2
    const val CONTENT_TYPE: Long = 3
    const val KEY_ID: Long = 4
    const val IV: Long = 5
    const val PARTIAL_IV: Long = 6
    const val CERTIFICATE_CHAIN: Long = 33
    const val CERTIFICATE_HASH: Long = 34
    const val EPHEMERAL_KEY: Long = -1
    const val SALT: Long = -20
    const val PARTY_U_IDENTITY: Long = -21
    const val PARTY_U_NONCE: Long = -22
    const val PARTY_U_OTHER: Long = -23
    const val PARTY_V_IDENTITY: Long = -24
    const val PARTY_V_NONCE: Long = -25
    const val PARTY_V_OTHER: Long = -26

    val UNDERSTOOD: List<CborItem> = listOf(
        ALGORITHM,
        CRITICAL,
        CONTENT_TYPE,
        KEY_ID,
        IV,
        PARTIAL_IV,
        CERTIFICATE_CHAIN,
        CERTIFICATE_HASH,
        EPHEMERAL_KEY,
        SALT,
        PARTY_U_IDENTITY,
        PARTY_U_NONCE,
        PARTY_U_OTHER,
        PARTY_V_IDENTITY,
        PARTY_V_NONCE,
        PARTY_V_OTHER,
    ).map { label -> CborInteger.of(label) }
}
