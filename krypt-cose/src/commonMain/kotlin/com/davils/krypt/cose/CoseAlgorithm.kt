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

package com.davils.krypt.cose

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.cose.key.CoseCurve

/**
 * An algorithm of the COSE registry that krypt implements, by RFC 9053, RFC 8230 for RSA-PSS and RFC 9864 for the
 * fully specified signature algorithms.
 *
 * Every verification and decryption takes an explicit set of these as its allowlist; an algorithm of a message that is
 * not in it, or that krypt does not know, is refused before any key is touched. The crypto policy of the environment
 * applies on top. The ECDSA algorithms are bound to their curve: ES256 and ESP256 to P-256, ES384 and ESP384 to P-384,
 * ES512 and ESP512 to P-521. RFC 9864 deprecates the polymorphic ES256, ES384, ES512 and EdDSA in favour of the fully
 * specified ESP256, ESP384, ESP512, Ed25519 and Ed448.
 *
 * @property id the value of the algorithm in the COSE registry.
 * @property algorithmName the name of the algorithm in the COSE registry.
 * @property kind what the algorithm does.
 * @property signature the signature algorithm of krypt, or null for EdDSA, whose curve the key decides.
 * @property curve the only curve the signature algorithm accepts, or null.
 * @property mac the HMAC of krypt, or null.
 * @property tagBytes the length of the truncated MAC tag, or zero.
 * @property aead the AEAD of krypt, or null.
 * @property keyWrap the key wrap of krypt, or null.
 * @property kdf the HKDF of a key agreement, or null.
 * @since 1.0.0
 */
public enum class CoseAlgorithm(
    public val id: Long,
    public val algorithmName: String,
    public val kind: CoseAlgorithmKind,
    internal val signature: SignatureAlgorithm? = null,
    internal val curve: CoseCurve? = null,
    internal val mac: MacAlgorithm? = null,
    internal val tagBytes: Int = 0,
    internal val aead: AeadAlgorithm? = null,
    internal val keyWrap: KeyWrapAlgorithm? = null,
    internal val kdf: KdfAlgorithm? = null,
) {
    /**
     * ECDSA with SHA-256 on P-256, deprecated by RFC 9864 for [Esp256].
     *
     * @since 1.0.0
     */
    Es256(
        id = -7,
        algorithmName = "ES256",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.EcdsaSha256,
        curve = CoseCurve.P256,
    ),

    /**
     * ECDSA with SHA-384 on P-384, deprecated by RFC 9864 for [Esp384].
     *
     * @since 1.0.0
     */
    Es384(
        id = -35,
        algorithmName = "ES384",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.EcdsaSha384,
        curve = CoseCurve.P384,
    ),

    /**
     * ECDSA with SHA-512 on P-521, deprecated by RFC 9864 for [Esp512].
     *
     * @since 1.0.0
     */
    Es512(
        id = -36,
        algorithmName = "ES512",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.EcdsaSha512,
        curve = CoseCurve.P521,
    ),

    /**
     * ECDSA using P-256 and SHA-256 of RFC 9864.
     *
     * @since 1.0.0
     */
    Esp256(
        id = -9,
        algorithmName = "ESP256",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.EcdsaSha256,
        curve = CoseCurve.P256,
    ),

    /**
     * ECDSA using P-384 and SHA-384 of RFC 9864.
     *
     * @since 1.0.0
     */
    Esp384(
        id = -51,
        algorithmName = "ESP384",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.EcdsaSha384,
        curve = CoseCurve.P384,
    ),

    /**
     * ECDSA using P-521 and SHA-512 of RFC 9864.
     *
     * @since 1.0.0
     */
    Esp512(
        id = -52,
        algorithmName = "ESP512",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.EcdsaSha512,
        curve = CoseCurve.P521,
    ),

    /**
     * EdDSA with the curve of the key, Ed25519 or Ed448, deprecated by RFC 9864 for [Ed25519] and [Ed448].
     *
     * @since 1.0.0
     */
    EdDsa(id = -8, algorithmName = "EdDSA", kind = CoseAlgorithmKind.Signature),

    /**
     * EdDSA using Ed25519 of RFC 9864.
     *
     * @since 1.0.0
     */
    Ed25519(
        id = -19,
        algorithmName = "Ed25519",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.Ed25519,
        curve = CoseCurve.Ed25519,
    ),

    /**
     * EdDSA using Ed448 of RFC 9864, where the platform has it.
     *
     * @since 1.0.0
     */
    Ed448(
        id = -53,
        algorithmName = "Ed448",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.Ed448,
        curve = CoseCurve.Ed448,
    ),

    /**
     * RSASSA-PSS with SHA-256 of RFC 8230.
     *
     * @since 1.0.0
     */
    Ps256(
        id = -37,
        algorithmName = "PS256",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.RsaPssSha256,
    ),

    /**
     * RSASSA-PSS with SHA-384 of RFC 8230.
     *
     * @since 1.0.0
     */
    Ps384(
        id = -38,
        algorithmName = "PS384",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.RsaPssSha384,
    ),

    /**
     * RSASSA-PSS with SHA-512 of RFC 8230.
     *
     * @since 1.0.0
     */
    Ps512(
        id = -39,
        algorithmName = "PS512",
        kind = CoseAlgorithmKind.Signature,
        signature = SignatureAlgorithm.RsaPssSha512,
    ),

    /**
     * HMAC with SHA-256, its tag truncated to 64 bits.
     *
     * @since 1.0.0
     */
    Hmac256Truncated64(
        id = 4,
        algorithmName = "HMAC 256/64",
        kind = CoseAlgorithmKind.Mac,
        mac = MacAlgorithm.HmacSha256,
        tagBytes = 8,
    ),

    /**
     * HMAC with SHA-256.
     *
     * @since 1.0.0
     */
    Hmac256(
        id = 5,
        algorithmName = "HMAC 256/256",
        kind = CoseAlgorithmKind.Mac,
        mac = MacAlgorithm.HmacSha256,
        tagBytes = 32,
    ),

    /**
     * HMAC with SHA-384.
     *
     * @since 1.0.0
     */
    Hmac384(
        id = 6,
        algorithmName = "HMAC 384/384",
        kind = CoseAlgorithmKind.Mac,
        mac = MacAlgorithm.HmacSha384,
        tagBytes = 48,
    ),

    /**
     * HMAC with SHA-512.
     *
     * @since 1.0.0
     */
    Hmac512(
        id = 7,
        algorithmName = "HMAC 512/512",
        kind = CoseAlgorithmKind.Mac,
        mac = MacAlgorithm.HmacSha512,
        tagBytes = 64,
    ),

    /**
     * AES-GCM with a 128-bit key and a 128-bit tag.
     *
     * @since 1.0.0
     */
    A128Gcm(
        id = 1,
        algorithmName = "A128GCM",
        kind = CoseAlgorithmKind.ContentEncryption,
        aead = AeadAlgorithm.Aes128Gcm,
    ),

    /**
     * AES-GCM with a 192-bit key and a 128-bit tag, where the platform has it.
     *
     * @since 1.0.0
     */
    A192Gcm(
        id = 2,
        algorithmName = "A192GCM",
        kind = CoseAlgorithmKind.ContentEncryption,
        aead = AeadAlgorithm.Aes192Gcm,
    ),

    /**
     * AES-GCM with a 256-bit key and a 128-bit tag.
     *
     * @since 1.0.0
     */
    A256Gcm(
        id = 3,
        algorithmName = "A256GCM",
        kind = CoseAlgorithmKind.ContentEncryption,
        aead = AeadAlgorithm.Aes256Gcm,
    ),

    /**
     * ChaCha20-Poly1305 with a 256-bit key, where the platform has it.
     *
     * @since 1.0.0
     */
    ChaCha20Poly1305(
        id = 24,
        algorithmName = "ChaCha20/Poly1305",
        kind = CoseAlgorithmKind.ContentEncryption,
        aead = AeadAlgorithm.ChaCha20Poly1305,
    ),

    /**
     * The key of the recipient is the content key itself.
     *
     * @since 1.0.0
     */
    Direct(id = -6, algorithmName = "direct", kind = CoseAlgorithmKind.KeyDistribution),

    /**
     * The content key is wrapped with AES key wrap and a 128-bit key.
     *
     * @since 1.0.0
     */
    A128Kw(
        id = -3,
        algorithmName = "A128KW",
        kind = CoseAlgorithmKind.KeyDistribution,
        keyWrap = KeyWrapAlgorithm.Aes128Kw,
    ),

    /**
     * The content key is wrapped with AES key wrap and a 192-bit key, where the platform has it.
     *
     * @since 1.0.0
     */
    A192Kw(
        id = -4,
        algorithmName = "A192KW",
        kind = CoseAlgorithmKind.KeyDistribution,
        keyWrap = KeyWrapAlgorithm.Aes192Kw,
    ),

    /**
     * The content key is wrapped with AES key wrap and a 256-bit key.
     *
     * @since 1.0.0
     */
    A256Kw(
        id = -5,
        algorithmName = "A256KW",
        kind = CoseAlgorithmKind.KeyDistribution,
        keyWrap = KeyWrapAlgorithm.Aes256Kw,
    ),

    /**
     * The content key is derived with HKDF-SHA-256 from ECDH of an ephemeral key and the key of the recipient.
     *
     * @since 1.0.0
     */
    EcdhEsHkdf256(
        id = -25,
        algorithmName = "ECDH-ES + HKDF-256",
        kind = CoseAlgorithmKind.KeyDistribution,
        kdf = KdfAlgorithm.HkdfSha256,
    ),

    /**
     * The content key is derived with HKDF-SHA-512 from ECDH of an ephemeral key and the key of the recipient.
     *
     * @since 1.0.0
     */
    EcdhEsHkdf512(
        id = -26,
        algorithmName = "ECDH-ES + HKDF-512",
        kind = CoseAlgorithmKind.KeyDistribution,
        kdf = KdfAlgorithm.HkdfSha512,
    ),

    /**
     * The content key is wrapped with AES-128 key wrap under a key derived with HKDF-SHA-256 from ECDH of an
     * ephemeral key and the key of the recipient.
     *
     * @since 1.0.0
     */
    EcdhEsA128Kw(
        id = -29,
        algorithmName = "ECDH-ES + A128KW",
        kind = CoseAlgorithmKind.KeyDistribution,
        keyWrap = KeyWrapAlgorithm.Aes128Kw,
        kdf = KdfAlgorithm.HkdfSha256,
    ),

    /**
     * The content key is wrapped with AES-192 key wrap under a key derived with HKDF-SHA-256 from ECDH of an
     * ephemeral key and the key of the recipient.
     *
     * @since 1.0.0
     */
    EcdhEsA192Kw(
        id = -30,
        algorithmName = "ECDH-ES + A192KW",
        kind = CoseAlgorithmKind.KeyDistribution,
        keyWrap = KeyWrapAlgorithm.Aes192Kw,
        kdf = KdfAlgorithm.HkdfSha256,
    ),

    /**
     * The content key is wrapped with AES-256 key wrap under a key derived with HKDF-SHA-256 from ECDH of an
     * ephemeral key and the key of the recipient.
     *
     * @since 1.0.0
     */
    EcdhEsA256Kw(
        id = -31,
        algorithmName = "ECDH-ES + A256KW",
        kind = CoseAlgorithmKind.KeyDistribution,
        keyWrap = KeyWrapAlgorithm.Aes256Kw,
        kdf = KdfAlgorithm.HkdfSha256,
    ),
    ;

    /**
     * The algorithms by their value.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the algorithm with the value [id].
         *
         * @param id the value in the COSE registry.
         * @return the algorithm, or null if krypt does not implement it.
         * @since 1.0.0
         */
        public fun of(id: Long): CoseAlgorithm? = entries.firstOrNull { algorithm -> algorithm.id == id }
    }
}
