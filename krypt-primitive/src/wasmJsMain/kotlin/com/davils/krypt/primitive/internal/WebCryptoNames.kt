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

package com.davils.krypt.primitive.internal

import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.SignatureAlgorithm

@OptIn(LegacyCryptography::class)
internal object WebCryptoNames {
    const val ECDSA: String = "ECDSA"
    const val ECDH: String = "ECDH"
    const val RSA_PSS: String = "RSA-PSS"
    const val RSA_PKCS1: String = "RSASSA-PKCS1-v1_5"
    const val RSA_OAEP: String = "RSA-OAEP"
    const val DERIVE: String = "deriveBits"
    const val SIGN_VERIFY: String = "sign,verify"
    const val AES_GCM: String = "AES-GCM"
    const val AES_CBC: String = "AES-CBC"
    const val AES_KW: String = "AES-KW"
    const val CHACHA: String = "ChaCha20-Poly1305"
    const val SHA_256: String = "SHA-256"

    private val DIGESTS: Map<DigestAlgorithm, String> = mapOf(
        DigestAlgorithm.Sha256 to SHA_256,
        DigestAlgorithm.Sha384 to "SHA-384",
        DigestAlgorithm.Sha512 to "SHA-512",
        DigestAlgorithm.Sha3256 to "SHA3-256",
        DigestAlgorithm.Sha3384 to "SHA3-384",
        DigestAlgorithm.Sha3512 to "SHA3-512",
        DigestAlgorithm.Sha1 to "SHA-1",
    )

    private val SIGNATURE_KEYS: Map<SignatureAlgorithm, String> = mapOf(
        SignatureAlgorithm.Ed25519 to "Ed25519",
        SignatureAlgorithm.Ed448 to "Ed448",
        SignatureAlgorithm.EcdsaSha256 to ECDSA,
        SignatureAlgorithm.EcdsaSha384 to ECDSA,
        SignatureAlgorithm.EcdsaSha512 to ECDSA,
        SignatureAlgorithm.EcdsaSha1 to ECDSA,
        SignatureAlgorithm.RsaPssSha256 to RSA_PSS,
        SignatureAlgorithm.RsaPssSha384 to RSA_PSS,
        SignatureAlgorithm.RsaPssSha512 to RSA_PSS,
        SignatureAlgorithm.RsaPkcs1Sha256 to RSA_PKCS1,
        SignatureAlgorithm.RsaPkcs1Sha384 to RSA_PKCS1,
        SignatureAlgorithm.RsaPkcs1Sha512 to RSA_PKCS1,
        SignatureAlgorithm.RsaPkcs1Sha1 to RSA_PKCS1,
    )

    private val GENERATION: Map<KeyFamily, Pair<String, String>> = mapOf(
        KeyFamily.Ed25519 to ("Ed25519" to SIGN_VERIFY),
        KeyFamily.Ed448 to ("Ed448" to SIGN_VERIFY),
        KeyFamily.Ec to (ECDSA to SIGN_VERIFY),
        KeyFamily.Rsa to (RSA_PSS to SIGN_VERIFY),
        KeyFamily.X25519 to ("X25519" to DERIVE),
        KeyFamily.X448 to ("X448" to DERIVE),
    )

    fun digest(algorithm: DigestAlgorithm): String? = DIGESTS[algorithm]

    fun signatureKey(algorithm: SignatureAlgorithm): String? = SIGNATURE_KEYS[algorithm]

    fun generation(family: KeyFamily): Pair<String, String>? = GENERATION[family]
}
