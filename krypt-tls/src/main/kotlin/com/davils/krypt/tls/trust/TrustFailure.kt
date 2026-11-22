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

package com.davils.krypt.tls.trust

import com.davils.krypt.x509.path.PathFailure

/**
 * Why krypt refused the certificate chain of a peer.
 *
 * @since 1.0.0
 */
public enum class TrustFailure {
    /**
     * The peer sent no certificate or one krypt cannot read.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * No path leads from the certificate of the peer to a trust anchor.
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
     * The crypto policy forbids an algorithm or a key on the path.
     *
     * @since 1.0.0
     */
    AlgorithmNotPermitted,

    /**
     * A certificate on the path is not valid now.
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
     * The extended key usage does not allow the purpose: serverAuth for a server, clientAuth for a client.
     *
     * @since 1.0.0
     */
    Purpose,

    /**
     * The path is longer than a constraint or the limits allow.
     *
     * @since 1.0.0
     */
    PathTooLong,

    /**
     * A name violates the name constraints of an authority.
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
     * The revocation status of a certificate is unknown and the revocation mode fails hard.
     *
     * @since 1.0.0
     */
    RevocationUnknown,

    /**
     * The certificate of a server does not name the host the client connects to, by RFC 9525.
     *
     * @since 1.0.0
     */
    HostMismatch,

    /**
     * No key on the path matches a pin.
     *
     * @since 1.0.0
     */
    PinMismatch,

    /**
     * The certificate demands a stapled OCSP response by its TLS feature extension and the peer stapled none that
     * verifies.
     *
     * @since 1.0.0
     */
    MustStapleMissing,

    /**
     * The signed certificate timestamps do not satisfy the CT policy.
     *
     * @since 1.0.0
     */
    TransparencyNotCompliant,

    /**
     * The peer authorizer refused the peer.
     *
     * @since 1.0.0
     */
    Unauthorized,

    /**
     * The trust manager was asked about a peer of the other side, such as a server by a manager that checks clients.
     *
     * @since 1.0.0
     */
    WrongSide,
    ;

    /**
     * Mapping failures.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val MAXIMUM_CAUSES: Int = 32

        /**
         * Returns the failure of a path validation.
         *
         * @param failure the failure of krypt-x509.
         * @return the trust failure.
         * @since 1.0.0
         */
        public fun of(failure: PathFailure): TrustFailure = when (failure) {
            PathFailure.NoTrustedPath -> NoTrustedPath
            PathFailure.BadSignature -> BadSignature
            PathFailure.AlgorithmNotPermitted -> AlgorithmNotPermitted
            PathFailure.Expired -> Expired
            PathFailure.NotAnAuthority -> NotAnAuthority
            PathFailure.KeyUsage -> KeyUsage
            PathFailure.Purpose -> Purpose
            PathFailure.PathTooLong -> PathTooLong
            PathFailure.NameConstraints -> NameConstraints
            PathFailure.Policy -> Policy
            PathFailure.UnknownCriticalExtension -> UnknownCriticalExtension
            PathFailure.Revoked -> Revoked
            PathFailure.RevocationUnknown -> RevocationUnknown
        }

        /**
         * Finds the failure krypt refused a peer with in [throwable] or its causes, such as the
         * [javax.net.ssl.SSLHandshakeException] of a handshake, by type and never by message.
         *
         * At most 32 causes are followed, and a cycle of causes ends the search.
         *
         * @param throwable the failure of a handshake.
         * @return the trust failure, or null if krypt did not refuse the peer.
         * @since 1.0.0
         */
        public fun of(throwable: Throwable): TrustFailure? {
            val causes = generateSequence(throwable) { current -> current.cause }
            val bounded = causes.take(MAXIMUM_CAUSES)
            return bounded.filterIsInstance<TrustRefusedException>().firstOrNull()?.failure
        }
    }
}
