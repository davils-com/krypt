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

package com.davils.krypt.x509.path

/**
 * Why a certificate path is not valid.
 *
 * @since 1.0.0
 */
public enum class PathFailure {
    /**
     * No path leads from the certificate to a trust anchor.
     *
     * @since 1.0.0
     */
    NoTrustedPath,

    /**
     * A signature on the path is not valid.
     *
     * @since 1.0.0
     */
    BadSignature,

    /**
     * The crypto policy forbids an algorithm or a key on the path, or krypt cannot read a key.
     *
     * @since 1.0.0
     */
    AlgorithmNotPermitted,

    /**
     * A certificate is not valid at the time of validation.
     *
     * @since 1.0.0
     */
    Expired,

    /**
     * A certificate that issues another one is no certificate authority.
     *
     * @since 1.0.0
     */
    NotAnAuthority,

    /**
     * The key usage of a certificate forbids its use on the path.
     *
     * @since 1.0.0
     */
    KeyUsage,

    /**
     * The extended key usage of a certificate does not allow the purpose of the validation.
     *
     * @since 1.0.0
     */
    Purpose,

    /**
     * The path is longer than a path length constraint or the limits allow.
     *
     * @since 1.0.0
     */
    PathTooLong,

    /**
     * A name lies outside the permitted subtrees or within the excluded subtrees of an authority.
     *
     * @since 1.0.0
     */
    NameConstraints,

    /**
     * No acceptable certificate policy is valid for the path.
     *
     * @since 1.0.0
     */
    Policy,

    /**
     * A certificate has a critical extension krypt does not know.
     *
     * @since 1.0.0
     */
    UnknownCriticalExtension,

    /**
     * A certificate on the path is revoked.
     *
     * @since 1.0.0
     */
    Revoked,

    /**
     * The status of a certificate on the path is unknown and the validation requires it.
     *
     * @since 1.0.0
     */
    RevocationUnknown,
}
