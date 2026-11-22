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

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.UnsupportedAlgorithmException

internal object WebCryptoParameters {
    fun signatureImport(algorithm: SignatureAlgorithm, curve: EllipticCurve?): JsAny {
        val name = WebCryptoNames.signatureKey(
            algorithm,
        ) ?: throw UnsupportedAlgorithmException(algorithm.algorithmName)
        val hash = algorithm.digest?.let { digest -> WebCryptoNames.digest(digest) }
        val isRsa = name == WebCryptoNames.RSA_PSS || name == WebCryptoNames.RSA_PKCS1
        val ecdsa = curve?.takeIf { name == WebCryptoNames.ECDSA }?.let { found -> withCurve(name, found.curveName) }
        val rsa = hash?.takeIf { isRsa }?.let { found -> withHash(name, found) }
        return ecdsa ?: rsa ?: named(name)
    }

    fun signature(algorithm: SignatureAlgorithm): JsAny {
        val name = checkNotNull(WebCryptoNames.signatureKey(algorithm))
        val hash = algorithm.digest?.let { digest -> WebCryptoNames.digest(digest) }
        val saltLength = algorithm.digest?.outputBytes ?: 0
        val ecdsa = hash?.takeIf { name == WebCryptoNames.ECDSA }?.let { found -> ecdsaParameters(found) }
        val pss = pssParameters(saltLength).takeIf { name == WebCryptoNames.RSA_PSS }
        return ecdsa ?: pss ?: named(name)
    }

    fun agreement(algorithm: KeyAgreementAlgorithm): Pair<String, JsAny> {
        val curve = algorithm.curve ?: return algorithm.algorithmName to named(algorithm.algorithmName)
        return WebCryptoNames.ECDH to withCurve(WebCryptoNames.ECDH, curve.curveName)
    }

    fun generation(type: KeyType, name: String): JsAny {
        val curve = type.curve?.let { found -> withCurve(name, found.curveName) }
        val rsa = rsaGeneration(name, type.bits, WebCryptoNames.SHA_256).takeIf { type.family == KeyFamily.Rsa }
        return curve ?: rsa ?: named(name)
    }

    fun aead(algorithm: AeadAlgorithm): String = when (algorithm) {
        AeadAlgorithm.Aes128Gcm -> WebCryptoNames.AES_GCM
        AeadAlgorithm.Aes256Gcm -> WebCryptoNames.AES_GCM
        AeadAlgorithm.Aes192Gcm -> WebCryptoNames.AES_GCM
        AeadAlgorithm.ChaCha20Poly1305 -> WebCryptoNames.CHACHA
    }
}
