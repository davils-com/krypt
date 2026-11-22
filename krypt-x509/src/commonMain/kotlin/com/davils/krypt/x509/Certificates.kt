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

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.internal.CertificateCodec
import com.davils.krypt.x509.internal.CertificateCodec.writeTbs
import com.davils.krypt.x509.internal.KeyIdentifiers
import com.davils.krypt.x509.internal.SignatureChecks
import com.davils.krypt.x509.internal.TbsTemplate
import kotlinx.io.bytestring.ByteString

private const val LABEL: String = "CERTIFICATE"
private const val SERIAL_BYTES: Int = 20
private const val POSITIVE: Int = 0x7F
private const val MAXIMUM_CHAIN: Int = 256

/**
 * Reads, writes, verifies and issues X.509 certificates with the primitives of [crypto].
 *
 * Reading is strict: the DER of the certificate, its names and the extensions krypt knows must be valid, an extension
 * must not repeat, and the limits apply before anything is decoded. The object holds no key and is safe to share
 * between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the limits of reading.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class Certificates(public val crypto: Crypto, public val limits: X509Limits = X509Limits.Default) {
    /**
     * Reads a certificate in DER.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the certificate, or why it could not be read.
     * @since 1.0.0
     */
    public fun decode(encoded: ByteString): Outcome<Certificate, X509Failure> {
        val certificate = CertificateCodec.decodeOrNull(
            crypto,
            encoded,
            limits,
        ) ?: return Outcome.Failure(X509Failure.Malformed)
        return Outcome.Success(certificate)
    }

    /**
     * Reads every certificate of a PEM text, such as a chain, in order.
     *
     * @param text the text, possibly from an attacker; other blocks are skipped.
     * @return the certificates, at least one, or why they could not be read.
     * @since 1.0.0
     */
    public fun decodePem(text: String): Outcome<List<Certificate>, X509Failure> {
        val decoded = Pem.decode(text).getOrNull() ?: return Outcome.Failure(X509Failure.Malformed)
        val blocks = decoded.filter { block -> block.label == LABEL }
        val certificates = blocks.take(MAXIMUM_CHAIN).mapNotNull { block ->
            CertificateCodec.decodeOrNull(crypto, block.bytes, limits)
        }
        val isComplete = certificates.size == blocks.size && blocks.size in 1..MAXIMUM_CHAIN
        return when (isComplete) {
            true -> Outcome.Success(certificates)
            false -> Outcome.Failure(X509Failure.Malformed)
        }
    }

    /**
     * Writes [certificate] in PEM.
     *
     * @param certificate the certificate.
     * @return the PEM text.
     * @since 1.0.0
     */
    public fun encodePem(certificate: Certificate): String = Pem.encode(label = LABEL, bytes = certificate.encoded)

    /**
     * Verifies the signature of [certificate] with the public key of its issuer.
     *
     * @param certificate the certificate.
     * @param issuerKey the public key of the issuer.
     * @return [Verification.Valid] if the signature is valid and its algorithm and key are permitted by the policy and
     *   supported by the platform.
     * @since 1.0.0
     */
    public suspend fun verifySignature(certificate: Certificate, issuerKey: PublicKey): Verification =
        SignatureChecks.verify(
            crypto = crypto,
            algorithm = certificate.signatureAlgorithm,
            key = issuerKey,
            data = certificate.tbs,
            signature = certificate.signature,
        )

    /**
     * Returns the digest of the encoding of [certificate], its fingerprint.
     *
     * @param certificate the certificate.
     * @param digest the digest; SHA-256 by default.
     * @return the fingerprint.
     * @since 1.0.0
     */
    public suspend fun fingerprint(
        certificate: Certificate,
        digest: DigestAlgorithm = DigestAlgorithm.Sha256,
    ): ByteString = crypto.digests.digest(certificate.encoded, digest)

    /**
     * Returns the key identifier of [publicKey] by method 1 of RFC 7093: the leftmost 160 bits of the SHA-256 digest
     * of the key, for the subject and the authority key identifiers.
     *
     * @param publicKey the public key.
     * @return the identifier of 20 bytes.
     * @since 1.0.0
     */
    public suspend fun keyIdentifier(publicKey: PublicKey): ByteString = KeyIdentifiers.of(crypto, publicKey.encoded)

    /**
     * Issues a certificate signed by [signer].
     *
     * @param signer the signer of the issuer, possibly a key in an HSM; its public key is the one of a self-signed
     *   certificate.
     * @param block describes the certificate.
     * @return the certificate.
     * @throws IllegalArgumentException if the public key or the validity is missing or the validity is empty.
     * @since 1.0.0
     */
    public suspend fun issue(signer: Signer, block: CertificateBuilder.() -> Unit): Certificate {
        val builder = CertificateBuilder()
        builder.block()
        val publicKey = requireNotNull(builder.publicKey) { "A certificate needs the public key of its subject" }
        val notBefore = requireNotNull(builder.notBefore) { "A certificate needs the start of its validity" }
        val notAfter = requireNotNull(builder.notAfter) { "A certificate needs the end of its validity" }
        require(notBefore <= notAfter) { "The validity of a certificate ends after it starts" }
        val template = TbsTemplate(
            serialNumber = builder.serialNumber ?: randomSerial(),
            algorithm = signer.algorithm,
            issuer = builder.issuer ?: builder.subject,
            notBefore = notBefore,
            notAfter = notAfter,
            subject = builder.subject,
            subjectPublicKeyInfo = publicKey.encoded,
            extensions = builder.extensions,
        )
        val tbs = Der.encode { writeTbs(template) }
        val signature = signer.sign(tbs)
        val encoded = Der.encode {
            sequence {
                raw(tbs)
                raw(AlgorithmIdentifiers.encode(signer.algorithm))
                bitString(BitString(signature))
            }
        }
        return checkNotNull(
            CertificateCodec.decodeOrNull(crypto, encoded, limits),
        ) { "The issued certificate is not valid" }
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Certificates($limits)"

    private fun randomSerial(): DerInteger {
        val bytes = crypto.environment.random.bytes(SERIAL_BYTES)
        bytes[0] = ((bytes[0].toInt() and POSITIVE) or 1).toByte()
        return DerInteger.ofMagnitude(ByteString(bytes))
    }
}
