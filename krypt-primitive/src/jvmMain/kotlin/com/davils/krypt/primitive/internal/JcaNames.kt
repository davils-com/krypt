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
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private const val TAG_BITS: Int = 128
private const val TRAILER: Int = 1

@OptIn(LegacyCryptography::class)
internal object JcaNames {
    private const val RSA_PSS: String = "RSASSA-PSS"
    private const val EC: String = "EC"
    private const val RSA_OAEP: String = "RSA/ECB/OAEPPadding"
    private const val AES_GCM: String = "AES/GCM/NoPadding"
    private const val AES: String = "AES"

    private val PAIR_GENERATORS: Map<KeyFamily, String> = mapOf(KeyFamily.Ec to EC, KeyFamily.Rsa to "RSA")

    private val GENERATORS: Map<KeyType, String> = mapOf(
        KeyType.MlDsa44 to "ML-DSA-44",
        KeyType.MlDsa65 to "ML-DSA-65",
        KeyType.MlDsa87 to "ML-DSA-87",
        KeyType.MlKem768 to "ML-KEM-768",
        KeyType.MlKem1024 to "ML-KEM-1024",
    )

    private val SIGNATURES: Map<SignatureAlgorithm, String> = mapOf(
        SignatureAlgorithm.Ed25519 to "Ed25519",
        SignatureAlgorithm.Ed448 to "Ed448",
        SignatureAlgorithm.EcdsaSha256 to "SHA256withECDSAinP1363Format",
        SignatureAlgorithm.EcdsaSha384 to "SHA384withECDSAinP1363Format",
        SignatureAlgorithm.EcdsaSha512 to "SHA512withECDSAinP1363Format",
        SignatureAlgorithm.EcdsaSha1 to "SHA1withECDSAinP1363Format",
        SignatureAlgorithm.RsaPssSha256 to RSA_PSS,
        SignatureAlgorithm.RsaPssSha384 to RSA_PSS,
        SignatureAlgorithm.RsaPssSha512 to RSA_PSS,
        SignatureAlgorithm.RsaPkcs1Sha256 to "SHA256withRSA",
        SignatureAlgorithm.RsaPkcs1Sha384 to "SHA384withRSA",
        SignatureAlgorithm.RsaPkcs1Sha512 to "SHA512withRSA",
        SignatureAlgorithm.RsaPkcs1Sha1 to "SHA1withRSA",
        SignatureAlgorithm.MlDsa44 to "ML-DSA-44",
        SignatureAlgorithm.MlDsa65 to "ML-DSA-65",
        SignatureAlgorithm.MlDsa87 to "ML-DSA-87",
    )

    fun digest(algorithm: DigestAlgorithm): String = when (algorithm) {
        DigestAlgorithm.Sha256 -> "SHA-256"
        DigestAlgorithm.Sha384 -> "SHA-384"
        DigestAlgorithm.Sha512 -> "SHA-512"
        DigestAlgorithm.Sha3256 -> "SHA3-256"
        DigestAlgorithm.Sha3384 -> "SHA3-384"
        DigestAlgorithm.Sha3512 -> "SHA3-512"
        DigestAlgorithm.Sha1 -> "SHA-1"
        DigestAlgorithm.Md5 -> "MD5"
    }

    fun mac(algorithm: MacAlgorithm): String = when (algorithm) {
        MacAlgorithm.HmacSha256 -> "HmacSHA256"
        MacAlgorithm.HmacSha384 -> "HmacSHA384"
        MacAlgorithm.HmacSha512 -> "HmacSHA512"
    }

    fun hmacOf(digest: DigestAlgorithm): String = "Hmac" + digest(digest).replace(oldValue = "-", newValue = "")

    fun keyFactory(family: KeyFamily): String = when (family) {
        KeyFamily.Ed25519 -> "Ed25519"
        KeyFamily.Ed448 -> "Ed448"
        KeyFamily.Ec -> EC
        KeyFamily.Rsa -> "RSA"
        KeyFamily.X25519 -> "X25519"
        KeyFamily.X448 -> "X448"
        KeyFamily.MlDsa -> "ML-DSA"
        KeyFamily.MlKem -> "ML-KEM"
    }

    fun generator(type: KeyType): String = GENERATORS[type] ?: keyFactory(type.family)

    fun keyPairGenerator(type: KeyType): String = PAIR_GENERATORS[type.family] ?: generator(type)

    fun signature(algorithm: SignatureAlgorithm): String = SIGNATURES.getValue(algorithm)

    fun curve(curve: EllipticCurve): String = when (curve) {
        EllipticCurve.P256 -> "secp256r1"
        EllipticCurve.P384 -> "secp384r1"
        EllipticCurve.P521 -> "secp521r1"
    }

    fun agreement(algorithm: KeyAgreementAlgorithm): String = when (algorithm) {
        KeyAgreementAlgorithm.X25519 -> "X25519"
        KeyAgreementAlgorithm.X448 -> "X448"
        KeyAgreementAlgorithm.EcdhP256 -> "ECDH"
        KeyAgreementAlgorithm.EcdhP384 -> "ECDH"
        KeyAgreementAlgorithm.EcdhP521 -> "ECDH"
    }

    fun aead(algorithm: AeadAlgorithm): String = when (algorithm) {
        AeadAlgorithm.Aes128Gcm -> AES_GCM
        AeadAlgorithm.Aes256Gcm -> AES_GCM
        AeadAlgorithm.Aes192Gcm -> AES_GCM
        AeadAlgorithm.ChaCha20Poly1305 -> "ChaCha20-Poly1305"
    }

    fun aeadKey(algorithm: AeadAlgorithm): String = when (algorithm) {
        AeadAlgorithm.Aes128Gcm -> AES
        AeadAlgorithm.Aes256Gcm -> AES
        AeadAlgorithm.Aes192Gcm -> AES
        AeadAlgorithm.ChaCha20Poly1305 -> "ChaCha20"
    }

    fun aeadSpec(algorithm: AeadAlgorithm, nonce: ByteArray): AlgorithmParameterSpec = when (algorithm) {
        AeadAlgorithm.Aes128Gcm -> GCMParameterSpec(TAG_BITS, nonce)
        AeadAlgorithm.Aes256Gcm -> GCMParameterSpec(TAG_BITS, nonce)
        AeadAlgorithm.Aes192Gcm -> GCMParameterSpec(TAG_BITS, nonce)
        AeadAlgorithm.ChaCha20Poly1305 -> IvParameterSpec(nonce)
    }

    fun rsaCipher(algorithm: AsymmetricEncryptionAlgorithm): String = when (algorithm) {
        AsymmetricEncryptionAlgorithm.RsaOaepSha256 -> RSA_OAEP
        AsymmetricEncryptionAlgorithm.RsaOaepSha384 -> RSA_OAEP
        AsymmetricEncryptionAlgorithm.RsaOaepSha512 -> RSA_OAEP
        AsymmetricEncryptionAlgorithm.RsaPkcs1 -> "RSA/ECB/PKCS1Padding"
    }

    fun oaep(algorithm: AsymmetricEncryptionAlgorithm): AlgorithmParameterSpec? = algorithm.digest?.let { digest ->
        val name = digest(digest)
        OAEPParameterSpec(name, "MGF1", MGF1ParameterSpec(name), PSource.PSpecified.DEFAULT)
    }

    fun pss(algorithm: SignatureAlgorithm): AlgorithmParameterSpec? {
        val digest = algorithm.digest?.takeIf { algorithm.algorithmName.startsWith("RSASSA-PSS") } ?: return null
        val name = digest(digest)
        return PSSParameterSpec(name, "MGF1", MGF1ParameterSpec(name), digest.outputBytes, TRAILER)
    }
}
