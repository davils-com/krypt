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

package com.davils.krypt.keystore.internal

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import kotlinx.io.bytestring.ByteString

internal sealed interface MacParts {
    val tag: ByteString

    data class Classic(
        val digest: DigestAlgorithm?,
        override val tag: ByteString,
        val salt: ByteString,
        val iterations: Int,
    ) : MacParts

    data class Pbmac1(
        val kdf: DigestAlgorithm?,
        val salt: ByteString,
        val iterations: Int,
        val keyBytes: Int,
        val mac: MacAlgorithm?,
        override val tag: ByteString,
    ) : MacParts
}
