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

package com.davils.krypt.cms

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.enveloped.ContentEncryption
import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.cms.enveloped.EncryptedData
import com.davils.krypt.cms.enveloped.EnvelopedData
import com.davils.krypt.cms.enveloped.Recipient
import com.davils.krypt.cms.internal.EnvelopedEngine
import com.davils.krypt.cms.internal.SignedCodec
import com.davils.krypt.cms.internal.SignedVerifier
import com.davils.krypt.cms.internal.SignedWriter
import com.davils.krypt.cms.internal.SignerSpec
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.cms.signed.SignedDataBuilder
import com.davils.krypt.cms.signed.SignerBuilder
import com.davils.krypt.cms.signed.SignerInfo
import com.davils.krypt.cms.signed.VerifiedSigner
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * The Cryptographic Message Syntax of RFC 5652: signed data with signed attributes, countersignatures and time-stamp
 * tokens, enveloped and authenticated-enveloped data for several kinds of recipients, and encrypted data.
 *
 * Every encoding krypt reads must be strict DER: BER, such as the indefinite lengths and constructed octet strings
 * of streamed messages, is refused as [CmsFailure.Malformed], and so are signed and authenticated attributes out of
 * DER order. Other sets, such as the certificates, which PKCS #7 producers like the time-stamp authority of OpenSSL
 * write unsorted, are read in any order; krypt writes every set sorted. Every structure is read within [limits],
 * checked before any work. The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the limits of reading and writing.
 * @constructor Works with [crypto] within [limits].
 * @since 1.0.0
 */
public class Cms(public val crypto: Crypto, public val limits: CmsLimits = CmsLimits.Default) {
    internal val signedCodec: SignedCodec = SignedCodec(crypto, limits)
    internal val signedWriter: SignedWriter = SignedWriter(crypto, limits)
    private val signedVerifier = SignedVerifier(crypto = crypto, codec = signedCodec, limits = limits)
    private val envelopedEngine = EnvelopedEngine(crypto, limits)

    /**
     * Signs [content] for every signer that [block] adds.
     *
     * Each signer signs through its [Signer], so its key may stay in an HSM. ECDSA, RSA-PSS (RFC 4056), RSA PKCS #1
     * v1.5 (where the policy permits it for new signatures), Ed25519 and Ed448 (RFC 8419) and ML-DSA (RFC 9882) are
     * supported.
     *
     * @param content the content, at most [CmsLimits.maximumContentBytes].
     * @param block describes the signers and the message.
     * @return the signed data in its ContentInfo.
     * @throws IllegalArgumentException if there is no signer or more than [CmsLimits.maximumSigners], a certificate
     *   does not match its signer, a key identifier is asked for but missing, Ed448 is asked to sign attributes, a
     *   signer without signed attributes signs a content type other than id-data, an attribute is duplicated or a
     *   limit is broken.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm.
     * @since 1.0.0
     */
    public suspend fun sign(content: ByteString, block: SignedDataBuilder.() -> Unit): SignedData {
        val builder = SignedDataBuilder()
        builder.block()
        return decoded(signedWriter.sign(content, builder))
    }

    /**
     * Reads signed data in DER, as a ContentInfo of type id-signedData.
     *
     * Certificates and revocation lists are read with the default limits of X.509; attribute certificates and other
     * revocation formats are refused. Countersignatures are read up to [CmsLimits.maximumNesting] deep.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the signed data, which is not verified yet, or [CmsFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeSigned(encoded: ByteString): Outcome<SignedData, CmsFailure> {
        val decoded = signedCodec.decode(encoded)?.let { found -> Outcome.Success(found) }
        return decoded ?: Outcome.Failure(CmsFailure.Malformed)
    }

    /**
     * Verifies every signer of [signedData], which must have at least one.
     *
     * A signer without signed attributes signs only the content, not its type, so RFC 5652 section 5.3 allows it only
     * for content of type id-data: for any other type it gives [CmsFailure.AttributeMismatch]. With signed attributes
     * the content-type attribute must name the type of the encapsulated content.
     *
     * @param signedData the signed data.
     * @param content the detached content, or null to verify the content in the message.
     * @param parameters the certificates and the path validation.
     * @return every signer with its certificate, or the first failure.
     * @since 1.0.0
     */
    public suspend fun verify(
        signedData: SignedData,
        content: ByteString? = null,
        parameters: SignatureParameters = SignatureParameters(),
    ): Outcome<List<VerifiedSigner>, CmsFailure> {
        val verified = mutableListOf<VerifiedSigner>()
        val failure = signedData.signers.firstNotNullOfOrNull { signer ->
            when (
                val outcome = verifySigner(
                    signedData = signedData,
                    signer = signer,
                    content = content,
                    parameters = parameters,
                )
            ) {
                is Outcome.Success -> null.also { verified += outcome.value }
                is Outcome.Failure -> outcome.failure
            }
        } ?: CmsFailure.SignerNotFound.takeIf { verified.isEmpty() }
        return failure?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(verified.toList())
    }

    /**
     * Verifies one signer of [signedData].
     *
     * The signer's certificate is found among the certificates of the message and of [parameters]. With signed
     * attributes the content-type attribute must name the content type, the message-digest attribute must match the
     * digest of the content, compared in constant time, and an ESS signing-certificate attribute, if present, must
     * name that certificate. The signature must verify with an algorithm and a key the policy accepts; with a path
     * validator in [parameters] the certificate must lead to a trust anchor.
     *
     * @param signedData the signed data.
     * @param signer one of its signers.
     * @param content the detached content, or null to verify the content in the message.
     * @param parameters the certificates and the path validation.
     * @return the signer with its certificate, or why it does not verify.
     * @since 1.0.0
     */
    public suspend fun verifySigner(
        signedData: SignedData,
        signer: SignerInfo,
        content: ByteString? = null,
        parameters: SignatureParameters = SignatureParameters(),
    ): Outcome<VerifiedSigner, CmsFailure> = signedVerifier.verify(
        data = signedData,
        signer = signer,
        content = content,
        parameters = parameters,
    )

    /**
     * Adds a countersignature by [signer] to [target], a signer of [signedData], by RFC 5652 section 11.4.
     *
     * The countersignature signs the signature value of [target]; its signed attributes carry no content type.
     *
     * @param signedData the signed data.
     * @param target the signer to countersign.
     * @param signer the countersigner.
     * @param certificate the countersigner's certificate.
     * @param block the options of the countersigner.
     * @return the signed data with the countersignature.
     * @throws IllegalArgumentException if [target] is not a signer of [signedData] or the options are invalid.
     * @since 1.0.0
     */
    public suspend fun countersign(
        signedData: SignedData,
        target: SignerInfo,
        signer: Signer,
        certificate: Certificate,
        block: SignerBuilder.() -> Unit = {},
    ): SignedData {
        val options = SignerBuilder()
        options.block()
        val spec = SignerSpec(signer = signer, certificate = certificate, options = options)
        return decoded(signedWriter.countersign(data = signedData, target = target, spec = spec))
    }

    /**
     * Verifies [countersignature], a countersignature of [target] in [signedData].
     *
     * @param signedData the signed data.
     * @param target the countersigned signer.
     * @param countersignature one of the countersignatures of [target].
     * @param parameters the certificates and the path validation.
     * @return the countersigner with its certificate, or why it does not verify.
     * @since 1.0.0
     */
    public suspend fun verifyCountersignature(
        signedData: SignedData,
        target: SignerInfo,
        countersignature: SignerInfo,
        parameters: SignatureParameters = SignatureParameters(),
    ): Outcome<VerifiedSigner, CmsFailure> = signedVerifier.verifyCountersignature(
        data = signedData,
        target = target,
        countersignature = countersignature,
        parameters = parameters,
    )

    /**
     * Adds [attribute] to the unsigned attributes of [target], such as a time-stamp token of
     * [com.davils.krypt.cms.timestamp.TimeStamps.signatureTimeStamp]. Values of a type already present are added to
     * it. The signature stays valid, since unsigned attributes are not signed.
     *
     * @param signedData the signed data.
     * @param target one of its signers.
     * @param attribute the attribute.
     * @return the signed data with the attribute.
     * @throws IllegalArgumentException if [target] is not a signer of [signedData] or the signer would carry more than
     *   [CmsLimits.maximumAttributes] attributes.
     * @since 1.0.0
     */
    public fun addUnsignedAttribute(signedData: SignedData, target: SignerInfo, attribute: Attribute): SignedData =
        decoded(signedWriter.withUnsigned(data = signedData, target = target, attribute = attribute))

    /**
     * Encrypts [content] under a fresh content-encryption key from the randomness of the environment and protects
     * that key for every recipient.
     *
     * With AES-GCM, the default, the result is AuthEnvelopedData of RFC 5083 with a random nonce of 12 bytes; a
     * content type other than id-data is then authenticated as an attribute. With AES-CBC it is EnvelopedData of
     * RFC 5652, which is not authenticated.
     *
     * AES-CBC is not authenticated: whoever changes the ciphertext changes the plaintext unnoticed, and a service that
     * shows, by its answer, its timing or what it does next, whether a changed message decrypted is a padding and
     * format oracle that reveals the plaintext, as in the Efail attacks. It is therefore refused unless
     * `isUnauthenticatedCbcAllowed` is true; set it only for legacy peers, and only when the content is
     * authenticated otherwise, such as signed content whose signature is verified before anything acts on it.
     *
     * @param content the content, at most [CmsLimits.maximumContentBytes].
     * @param recipients the recipients, 1 to [CmsLimits.maximumRecipients], of which at most one is a password.
     * @param encryption the content encryption; AES-256-GCM by default.
     * @param contentType the type of the content.
     * @param isUnauthenticatedCbcAllowed true to write unauthenticated EnvelopedData with AES-CBC; see above.
     * @return the enveloped data.
     * @throws IllegalArgumentException if a limit is broken, a recipient's key does not fit its kind or [encryption]
     *   is AES-CBC without [isUnauthenticatedCbcAllowed].
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm, a key or the
     *   iterations of a password recipient.
     * @since 1.0.0
     */
    public suspend fun envelop(
        content: ByteString,
        recipients: List<Recipient>,
        encryption: ContentEncryption = ContentEncryption.Aes256Gcm,
        contentType: ObjectIdentifier = ContentTypes.Data,
        isUnauthenticatedCbcAllowed: Boolean = false,
    ): EnvelopedData {
        val encoded = envelopedEngine.envelop(
            content = content,
            recipients = recipients,
            encryption = encryption,
            contentType = contentType,
            isUnauthenticatedCbcAllowed = isUnauthenticatedCbcAllowed,
        )
        return envelopedEngine.decodeOwn(encoded)
    }

    /**
     * Reads enveloped data of RFC 5652 or authenticated-enveloped data of RFC 5083 in DER, as a ContentInfo.
     *
     * The originator information is skipped. Recipients of a kind or with algorithms krypt does not know are kept
     * and reported as unusable when decrypting. As RFC 5083 section 2.1 asks, authenticated-enveloped data of a
     * content type other than id-data must carry authenticated attributes, and their content-type attribute must
     * name the content type of the encrypted content, which nothing else authenticates. Its tag must have the length
     * of the content encryption: 16 bytes for AES-GCM, the only length krypt accepts in the GCM parameters of
     * RFC 5084.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the enveloped data, or [CmsFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeEnveloped(encoded: ByteString): Outcome<EnvelopedData, CmsFailure> {
        val decoded = envelopedEngine.decode(encoded)?.let { found -> Outcome.Success(found) }
        return decoded ?: Outcome.Failure(CmsFailure.Malformed)
    }

    /**
     * Decrypts [envelopedData] with [credential].
     *
     * Every recipient that matches [credential] is tried. If none yields a content-encryption key of the right size,
     * the content is decrypted with a random key anyway, so a wrong key, a wrong password, a broken padding and a
     * wrong tag all end in the same [CmsFailure.DecryptionFailed] after the same work: there is no oracle, as for
     * the million-message attack on RSA.
     *
     * EnvelopedData with AES-CBC is refused with [CmsFailure.AlgorithmNotPermitted] before any key is used, unless
     * [isUnauthenticatedCbcAllowed] is true. Even then a successful decryption does not prove that the content is
     * unchanged.
     *
     * AES-CBC is not authenticated: whoever changes the ciphertext changes the plaintext unnoticed, and a service that
     * shows, by its answer, its timing or what it does next, whether a changed message decrypted is a padding and
     * format oracle that reveals the plaintext, as in the Efail attacks. It is therefore refused unless
     * `isUnauthenticatedCbcAllowed` is true; set it only for legacy peers, and only when the content is
     * authenticated otherwise, such as signed content whose signature is verified before anything acts on it.
     *
     * Password recipients derive their key with PBKDF2 within the iterations the policy accepts for verification;
     * HMAC-SHA-1, the default of PBKDF2 that OpenSSL writes, needs a policy that accepts SHA-1 for verification. A
     * password is tried with the first password recipient of the message only, so one decryption costs at most one
     * derivation of the most iterations the policy accepts, whatever the number of recipients; a message with more than
     * [CmsLimits.MAXIMUM_PASSWORD_RECIPIENTS] password recipients is refused as [CmsFailure.Malformed].
     * ML-KEM recipients work on the JVM only.
     *
     * @param envelopedData the enveloped data.
     * @param credential the key, the key-encryption key or the password of a recipient.
     * @param isUnauthenticatedCbcAllowed true to decrypt unauthenticated EnvelopedData with AES-CBC; see above.
     * @return the content, or why it could not be decrypted.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        envelopedData: EnvelopedData,
        credential: Credential,
        isUnauthenticatedCbcAllowed: Boolean = false,
    ): Outcome<ByteString, CmsFailure> = envelopedEngine.decrypt(
        data = envelopedData,
        credential = credential,
        isUnauthenticatedCbcAllowed = isUnauthenticatedCbcAllowed,
    )

    /**
     * Encrypts [content] with AES-CBC under [key], as EncryptedData of RFC 5652, which is not authenticated.
     *
     * AES-CBC is not authenticated: whoever changes the ciphertext changes the plaintext unnoticed, and a service that
     * shows, by its answer, its timing or what it does next, whether a changed message decrypted is a padding and
     * format oracle that reveals the plaintext, as in the Efail attacks. It is therefore refused unless
     * `isUnauthenticatedCbcAllowed` is true; set it only for legacy peers, and only when the content is
     * authenticated otherwise, such as signed content whose signature is verified before anything acts on it.
     *
     * @param content the content, at most [CmsLimits.maximumContentBytes].
     * @param key the key of 16 or 32 bytes, as [encryption] needs.
     * @param encryption AES-128-CBC or AES-256-CBC.
     * @param isUnauthenticatedCbcAllowed true to write unauthenticated EncryptedData at all; see above.
     * @return the encrypted data.
     * @throws IllegalArgumentException if [isUnauthenticatedCbcAllowed] is false, [encryption] is AES-GCM, the key has
     *   the wrong size or the content is too large.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        content: ByteString,
        key: SecretKey,
        encryption: ContentEncryption = ContentEncryption.Aes256Cbc,
        isUnauthenticatedCbcAllowed: Boolean = false,
    ): EncryptedData {
        val encoded = envelopedEngine.encrypt(
            content = content,
            key = key,
            encryption = encryption,
            isUnauthenticatedCbcAllowed = isUnauthenticatedCbcAllowed,
        )
        return envelopedEngine.decodeOwnEncrypted(encoded)
    }

    /**
     * Reads encrypted data of RFC 5652 in DER, as a ContentInfo.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the encrypted data, or [CmsFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeEncrypted(encoded: ByteString): Outcome<EncryptedData, CmsFailure> {
        val decoded = envelopedEngine.decodeEncrypted(encoded)?.let { found -> Outcome.Success(found) }
        return decoded ?: Outcome.Failure(CmsFailure.Malformed)
    }

    /**
     * Decrypts [encryptedData] with [key], with one failure for a wrong key and a wrong padding alike. EncryptedData
     * is AES-CBC, so it is refused with [CmsFailure.AlgorithmNotPermitted] unless [isUnauthenticatedCbcAllowed] is
     * true.
     *
     * AES-CBC is not authenticated: whoever changes the ciphertext changes the plaintext unnoticed, and a service that
     * shows, by its answer, its timing or what it does next, whether a changed message decrypted is a padding and
     * format oracle that reveals the plaintext, as in the Efail attacks. It is therefore refused unless
     * `isUnauthenticatedCbcAllowed` is true; set it only for legacy peers, and only when the content is
     * authenticated otherwise, such as signed content whose signature is verified before anything acts on it.
     *
     * @param encryptedData the encrypted data.
     * @param key the key.
     * @param isUnauthenticatedCbcAllowed true to decrypt unauthenticated EncryptedData at all; see above.
     * @return the content, or why it could not be decrypted.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        encryptedData: EncryptedData,
        key: SecretKey,
        isUnauthenticatedCbcAllowed: Boolean = false,
    ): Outcome<ByteString, CmsFailure> = envelopedEngine.decrypt(
        data = encryptedData,
        key = key,
        isUnauthenticatedCbcAllowed = isUnauthenticatedCbcAllowed,
    )

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Cms($limits)"

    private fun decoded(encoded: ByteString): SignedData = signedCodec.decodeOwn(encoded)
}
