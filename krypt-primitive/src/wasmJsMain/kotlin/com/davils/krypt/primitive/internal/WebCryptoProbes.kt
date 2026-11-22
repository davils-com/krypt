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

@file:OptIn(ExperimentalWasmJsInterop::class)

package com.davils.krypt.primitive.internal

import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm

private const val PROBE_KEY: Int = 32

@OptIn(LegacyCryptography::class)
internal object WebCryptoProbes {
    suspend fun supports(algorithm: Algorithm): Boolean = when (algorithm) {
        is DigestAlgorithm -> digest(algorithm)
        is MacAlgorithm -> true
        is AeadAlgorithm -> algorithm != AeadAlgorithm.ChaCha20Poly1305 || chaCha()
        is KeyWrapAlgorithm -> true
        is KdfAlgorithm -> true
        is SignatureAlgorithm -> signature(algorithm)
        is KeyAgreementAlgorithm -> agreement(algorithm.family, needsProbe = algorithm.curve == null)
        is AsymmetricEncryptionAlgorithm -> algorithm != AsymmetricEncryptionAlgorithm.RsaPkcs1
        is KemAlgorithm -> kem(algorithm)
    }

    private suspend fun kem(algorithm: KemAlgorithm): Boolean = algorithm.family != KeyFamily.MlKem &&
        agreement(
            algorithm.family,
            needsProbe = algorithm.family == KeyFamily.X25519,
        )

    suspend fun supports(type: KeyType): Boolean {
        val (name, keyUsages) = WebCryptoNames.generation(type.family) ?: return false
        val algorithm = WebCryptoParameters.generation(type, name)
        return attempt { generateKey(algorithm, usages(keyUsages)).settled() } != null
    }

    private suspend fun digest(algorithm: DigestAlgorithm): Boolean {
        val name = WebCryptoNames.digest(algorithm) ?: return false
        return attempt { digest(name, newBytes(0)).settled() } != null
    }

    private suspend fun chaCha(): Boolean {
        val algorithm = named(WebCryptoNames.CHACHA)
        return attempt {
            importKey(
                f = "raw",
                d = newBytes(PROBE_KEY),
                a = algorithm,
                e = false,
                u = usages("encrypt"),
            ).settled()
        } != null
    }

    private suspend fun signature(algorithm: SignatureAlgorithm): Boolean {
        val hasDigest = algorithm.digest?.let { digest -> WebCryptoNames.digest(digest) != null } ?: true
        val isNamed = WebCryptoNames.signatureKey(algorithm) != null
        val type = KeyType.entries.first { candidate -> candidate.family == algorithm.family }
        return isNamed && hasDigest && (type.family != KeyFamily.Ed448 || supports(type))
    }

    private suspend fun agreement(family: KeyFamily, needsProbe: Boolean): Boolean {
        val type = KeyType.entries.first { candidate -> candidate.family == family }
        return !needsProbe || supports(type)
    }

    private inline fun <R> attempt(block: () -> R): R? = try {
        block()
    } catch (_: WebCryptoRejection) {
        null
    }
}
