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

package com.davils.krypt.spiffe.x509

/**
 * Why a chain is no valid X.509-SVID of the X509-SVID specification.
 *
 * @since 1.0.0
 */
public enum class X509SvidFailure {
    /**
     * The chain holds no certificate.
     *
     * @since 1.0.0
     */
    EmptyChain,

    /**
     * The chain is longer than the limit, or the hint is longer than 1024 characters.
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * The leaf names no URI.
     *
     * @since 1.0.0
     */
    NoSpiffeId,

    /**
     * The leaf names more than one URI, which section 2 of the specification refuses.
     *
     * @since 1.0.0
     */
    SeveralUris,

    /**
     * The URI of the leaf is no SPIFFE id.
     *
     * @since 1.0.0
     */
    InvalidSpiffeId,

    /**
     * The SPIFFE id of the leaf has no path, as only a signing authority may.
     *
     * @since 1.0.0
     */
    TrustDomainId,

    /**
     * The leaf is a certificate authority.
     *
     * @since 1.0.0
     */
    CertificateAuthority,

    /**
     * The key usage of the leaf is missing, not critical, lacks `digitalSignature` or names `keyCertSign` or
     * `cRLSign`.
     *
     * @since 1.0.0
     */
    KeyUsage,

    /**
     * A signing certificate is no authority, lacks `keyCertSign`, or names a SPIFFE id with a path or of another
     * trust domain.
     *
     * @since 1.0.0
     */
    SigningCertificate,

    /**
     * The private key does not belong to the leaf.
     *
     * @since 1.0.0
     */
    KeyMismatch,

    /**
     * No bundle with X.509 authorities is known for the trust domain of the SPIFFE id.
     *
     * @since 1.0.0
     */
    NoBundle,

    /**
     * A certificate of the path is outside its validity.
     *
     * @since 1.0.0
     */
    Expired,

    /**
     * A certificate of the path is revoked.
     *
     * @since 1.0.0
     */
    Revoked,

    /**
     * The chain leads to no X.509 authority of the bundle by RFC 5280.
     *
     * @since 1.0.0
     */
    Untrusted,
}
