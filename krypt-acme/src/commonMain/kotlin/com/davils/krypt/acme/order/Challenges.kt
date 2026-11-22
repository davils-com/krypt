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

package com.davils.krypt.acme.order

import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.IdentifierType
import com.davils.krypt.acme.internal.Tokens
import com.davils.krypt.acme.internal.base64Url
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.Extension
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * What the holder of an account provisions to answer a challenge: the key authorization of RFC 8555 section 8.1,
 * the resource of `http-01`, the TXT record of `dns-01` and the validation certificate of `tls-alpn-01` of RFC 8737.
 *
 * Tokens are checked first: base64url without padding and at least 22 characters, so a hostile token cannot
 * escape the path of `http-01`. The instance is stateless and safe to share between threads.
 *
 * @property crypto the primitives, for the thumbprint, the digests and the validation certificate.
 * @constructor Answers challenges over [crypto].
 * @since 1.0.0
 */
public class Challenges(public val crypto: Crypto) {
    private val keys = JsonWebKeys(crypto)
    private val certificates = Certificates(crypto)

    /**
     * Returns the key authorization of [token] for [key]: the token, a period and the base64url of the SHA-256 JWK
     * thumbprint of RFC 7638 of the public key.
     *
     * @param token the token of the challenge.
     * @param accountKey the public key of the account.
     * @return the key authorization.
     * @throws IllegalArgumentException if [token] is no valid token.
     * @since 1.0.0
     */
    public suspend fun keyAuthorization(token: String, accountKey: PublicKey): String {
        require(Tokens.isValid(token)) { "The token is no base64url text of at least 128 bits" }
        val thumbprint = keys.thumbprint(keys.of(accountKey))
        return "$token.${base64Url(thumbprint)}"
    }

    /**
     * Returns the path the `http-01` resource is served at: `/.well-known/acme-challenge/` and the token. The body
     * is the key authorization, as `application/octet-stream`.
     *
     * @param token the token of the challenge.
     * @return the path.
     * @throws IllegalArgumentException if [token] is no valid token.
     * @since 1.0.0
     */
    public fun http01Path(token: String): String {
        require(Tokens.isValid(token)) { "The token is no base64url text of at least 128 bits" }
        return HTTP01_PREFIX + token
    }

    /**
     * Returns the name of the `dns-01` TXT record: `_acme-challenge.` and the domain name, without the `*.` of a
     * wildcard.
     *
     * @param identifier the DNS identifier.
     * @return the record name.
     * @throws IllegalArgumentException if [identifier] is no DNS name.
     * @since 1.0.0
     */
    public fun dns01Name(identifier: AcmeIdentifier): String {
        require(identifier.type == IdentifierType.Dns) { "dns-01 validates DNS names only" }
        return DNS01_LABEL + identifier.value.removePrefix(WILDCARD)
    }

    /**
     * Returns the value of the `dns-01` TXT record: the base64url of the SHA-256 digest of the key authorization.
     *
     * @param keyAuthorization the key authorization.
     * @return the record value.
     * @since 1.0.0
     */
    public suspend fun dns01Value(keyAuthorization: String): String = base64Url(digestOf(keyAuthorization))

    /**
     * Returns the critical `acmeIdentifier` extension of RFC 8737: an OCTET STRING with the SHA-256 digest of the
     * key authorization.
     *
     * @param keyAuthorization the key authorization.
     * @return the extension.
     * @since 1.0.0
     */
    public suspend fun tlsAlpn01Extension(keyAuthorization: String): Extension {
        val digest = digestOf(keyAuthorization)
        return Extension(id = ACME_IDENTIFIER, isCritical = true, value = Der.encode { octetString(digest) })
    }

    /**
     * Returns the self-signed validation certificate of `tls-alpn-01` by RFC 8737: one subject alternative name,
     * the DNS name or, by RFC 8738, the IP address of [identifier], and the critical `acmeIdentifier` extension. The
     * TLS server presents it when a client offers the ALPN protocol [ALPN_PROTOCOL].
     *
     * @param identifier the identifier to validate, no wildcard.
     * @param keyAuthorization the key authorization.
     * @param signer the key of the certificate, which also signs it.
     * @param validity how long the certificate is valid from now; seven days by default.
     * @return the certificate.
     * @throws IllegalArgumentException if [identifier] is a wildcard or [validity] is not positive.
     * @since 1.0.0
     */
    public suspend fun tlsAlpn01Certificate(
        identifier: AcmeIdentifier,
        keyAuthorization: String,
        signer: Signer,
        validity: Duration = DEFAULT_VALIDITY,
    ): Certificate {
        require(!identifier.isWildcard) { "tls-alpn-01 validates no wildcard" }
        require(validity.isPositive()) { "A validation certificate is valid for a while" }
        val name = identifier.generalName
        val extension = tlsAlpn01Extension(keyAuthorization)
        val now = crypto.environment.clock.now()
        return certificates.issue(signer) {
            publicKey = signer.publicKey
            notBefore = now
            notAfter = now + validity
            extensions {
                subjectAlternativeNames(names = listOf(name), critical = true)
                add(extension)
            }
        }
    }

    private suspend fun digestOf(keyAuthorization: String): ByteString =
        crypto.digests.digest(keyAuthorization.encodeToByteString(), DigestAlgorithm.Sha256)

    /**
     * Shows the type.
     *
     * @return the text.
     * @since 1.0.0
     */
    override fun toString(): String = "Challenges"

    /**
     * The constants of the challenges.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The ALPN protocol id of `tls-alpn-01`.
         *
         * @since 1.0.0
         */
        public const val ALPN_PROTOCOL: String = "acme-tls/1"

        /**
         * The prefix of the path of `http-01`.
         *
         * @since 1.0.0
         */
        public const val HTTP01_PREFIX: String = "/.well-known/acme-challenge/"

        /**
         * The label in front of the domain name of the `dns-01` record.
         *
         * @since 1.0.0
         */
        public const val DNS01_LABEL: String = "_acme-challenge."

        /**
         * The object identifier of the `acmeIdentifier` extension, `id-pe-acmeIdentifier` 1.3.6.1.5.5.7.1.31.
         *
         * @since 1.0.0
         */
        public val ACME_IDENTIFIER: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.1.31")

        private const val WILDCARD: String = "*."
        private val DEFAULT_VALIDITY: Duration = 7.days
    }
}
