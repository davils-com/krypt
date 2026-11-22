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

package com.davils.krypt.tls

import com.davils.krypt.core.algorithm.SignatureAlgorithm

/**
 * A signature scheme of the handshake and of certificates that krypt allows, in the order of preference.
 *
 * A scheme is offered only if the crypto policy of the environment permits its [algorithm] for verification. The RSA
 * PKCS #1 schemes sign only certificates and the handshakes of TLS 1.2; TLS 1.3 signs its handshake with RSA-PSS.
 *
 * @property schemeName the name of the scheme in JSSE and in the IANA registry.
 * @property algorithm the signature algorithm of krypt.
 * @since 1.0.0
 */
public enum class SignatureScheme(public val schemeName: String, public val algorithm: SignatureAlgorithm) {
    /**
     * ed25519.
     *
     * @since 1.0.0
     */
    Ed25519("ed25519", SignatureAlgorithm.Ed25519),

    /**
     * ed448.
     *
     * @since 1.0.0
     */
    Ed448("ed448", SignatureAlgorithm.Ed448),

    /**
     * ecdsa_secp256r1_sha256.
     *
     * @since 1.0.0
     */
    EcdsaSecp256r1Sha256("ecdsa_secp256r1_sha256", SignatureAlgorithm.EcdsaSha256),

    /**
     * ecdsa_secp384r1_sha384.
     *
     * @since 1.0.0
     */
    EcdsaSecp384r1Sha384("ecdsa_secp384r1_sha384", SignatureAlgorithm.EcdsaSha384),

    /**
     * ecdsa_secp521r1_sha512.
     *
     * @since 1.0.0
     */
    EcdsaSecp521r1Sha512("ecdsa_secp521r1_sha512", SignatureAlgorithm.EcdsaSha512),

    /**
     * rsa_pss_rsae_sha256.
     *
     * @since 1.0.0
     */
    RsaPssRsaeSha256("rsa_pss_rsae_sha256", SignatureAlgorithm.RsaPssSha256),

    /**
     * rsa_pss_rsae_sha384.
     *
     * @since 1.0.0
     */
    RsaPssRsaeSha384("rsa_pss_rsae_sha384", SignatureAlgorithm.RsaPssSha384),

    /**
     * rsa_pss_rsae_sha512.
     *
     * @since 1.0.0
     */
    RsaPssRsaeSha512("rsa_pss_rsae_sha512", SignatureAlgorithm.RsaPssSha512),

    /**
     * rsa_pkcs1_sha256.
     *
     * @since 1.0.0
     */
    RsaPkcs1Sha256("rsa_pkcs1_sha256", SignatureAlgorithm.RsaPkcs1Sha256),

    /**
     * rsa_pkcs1_sha384.
     *
     * @since 1.0.0
     */
    RsaPkcs1Sha384("rsa_pkcs1_sha384", SignatureAlgorithm.RsaPkcs1Sha384),

    /**
     * rsa_pkcs1_sha512.
     *
     * @since 1.0.0
     */
    RsaPkcs1Sha512("rsa_pkcs1_sha512", SignatureAlgorithm.RsaPkcs1Sha512),
}
