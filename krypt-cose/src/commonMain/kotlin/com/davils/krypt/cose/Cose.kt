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

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.internal.CoseException
import com.davils.krypt.cose.internal.CoseException.Companion.present
import com.davils.krypt.cose.internal.Encrypting
import com.davils.krypt.cose.internal.HeaderLabels
import com.davils.krypt.cose.internal.KeyCodec
import com.davils.krypt.cose.internal.Layer
import com.davils.krypt.cose.internal.Macing
import com.davils.krypt.cose.internal.MessageCodec
import com.davils.krypt.cose.internal.Permissions
import com.davils.krypt.cose.internal.Recipients
import com.davils.krypt.cose.internal.Request
import com.davils.krypt.cose.internal.Signing
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString

/**
 * Creates, reads, verifies and decrypts the COSE messages of RFC 9052 with the algorithms of RFC 9053, RFC 8230 and
 * RFC 9864: COSE_Sign1 and COSE_Sign, COSE_Mac0 and COSE_Mac, COSE_Encrypt0 and COSE_Encrypt with recipients, tagged
 * or untagged, with detached content and external additional data, and the certificates of RFC 9360.
 *
 * Every verification and decryption takes the keys to try and an explicit allowlist of algorithms. An algorithm
 * outside the allowlist, unknown to krypt or forbidden by the crypto policy is refused before any key is used; a key
 * is used only for an algorithm that fits its type, curve, `alg` and `key_ops`, and only when its key id matches the
 * `kid` of the message, if both have one. The `alg` of a message, a signature and an ECDH-ES recipient is read only
 * from the protected bucket, as RFC 9052 section 3.1 asks: one in the unprotected bucket refuses the message with
 * [CoseFailure.Malformed], so that nobody can swap it, for example for a shorter MAC. Only a direct or key wrap
 * recipient, whose protected bucket must be empty, names it unprotected. A `crit` parameter that names a label
 * neither krypt nor [criticalLabels] covers refuses the message. Decryption fails with [CoseFailure.DecryptionFailed]
 * for every wrong key, wrapped key or tag, so that it reveals nothing; MAC tags are compared in constant time.
 * Signatures, MACs and additional data cover the protected header parameters as they arrived, so a message read in
 * [CborMode.Relaxed] verifies as it was made.
 *
 * Creation draws every IV, content key and ephemeral key from the environment and throws on misuse, such as a key that
 * does not fit the algorithm or an `alg` among the unprotected header parameters. The object holds no key and is
 * safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the bounds of reading.
 * @property mode whether only deterministic CBOR is accepted when reading.
 * @property criticalLabels the labels of header parameters the application processes itself, which `crit` may name.
 * @constructor Works with [crypto] within [limits].
 * @since 1.0.0
 */
public class Cose(
    public val crypto: Crypto,
    public val limits: CoseLimits = CoseLimits.Default,
    public val mode: CborMode = CborMode.Deterministic,
    public val criticalLabels: Set<CborItem> = emptySet(),
) {
    private val understood = HeaderLabels.UNDERSTOOD + criticalLabels
    private val codec = MessageCodec(limits, mode)
    private val permissions = Permissions(crypto)
    private val recipients = Recipients(
        crypto = crypto,
        permissions = permissions,
        keyCodec = KeyCodec(crypto),
        understood = understood,
    )
    private val signing = Signing(crypto = crypto, permissions = permissions, understood = understood)
    private val macing = Macing(
        crypto = crypto,
        permissions = permissions,
        recipients = recipients,
        understood = understood,
    )
    private val encrypting = Encrypting(
        crypto = crypto,
        permissions = permissions,
        recipients = recipients,
        understood = understood,
    )
    private val certificates = Certificates(crypto)

    /**
     * Reads a tagged COSE message of any type.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed] if it is untagged, of an unknown tag or broken.
     * @since 1.0.0
     */
    public fun decode(encoded: ByteString): Outcome<CoseMessage, CoseFailure> = CoseException.outcome {
        codec.message(codec.item(encoded))
    }

    /**
     * Reads a COSE_Sign1, tagged with 18 or untagged.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeSign1(encoded: ByteString): Outcome<CoseSign1, CoseFailure> = CoseException.outcome {
        codec.sign1(codec.item(encoded))
    }

    /**
     * Reads a COSE_Sign, tagged with 98 or untagged.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeSign(encoded: ByteString): Outcome<CoseSign, CoseFailure> = CoseException.outcome {
        codec.sign(codec.item(encoded))
    }

    /**
     * Reads a COSE_Mac0, tagged with 17 or untagged.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeMac0(encoded: ByteString): Outcome<CoseMac0, CoseFailure> = CoseException.outcome {
        codec.mac0(codec.item(encoded))
    }

    /**
     * Reads a COSE_Mac, tagged with 97 or untagged.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeMac(encoded: ByteString): Outcome<CoseMac, CoseFailure> = CoseException.outcome {
        codec.mac(codec.item(encoded))
    }

    /**
     * Reads a COSE_Encrypt0, tagged with 16 or untagged.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeEncrypt0(encoded: ByteString): Outcome<CoseEncrypt0, CoseFailure> = CoseException.outcome {
        codec.encrypt0(codec.item(encoded))
    }

    /**
     * Reads a COSE_Encrypt, tagged with 96 or untagged.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the message, or [CoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeEncrypt(encoded: ByteString): Outcome<CoseEncrypt, CoseFailure> = CoseException.outcome {
        codec.encrypt(codec.item(encoded))
    }

    /**
     * Signs [payload] as a COSE_Sign1.
     *
     * @param payload the content.
     * @param signer the key, the algorithm and the header parameters.
     * @param externalAad data the signature covers that travels apart; none by default.
     * @param isDetached whether the payload is left out of the message.
     * @return the message.
     * @throws IllegalArgumentException if a header label is in both buckets or the headers name another algorithm.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun sign1(
        payload: ByteString,
        signer: CoseSigner,
        externalAad: ByteString = ByteString(),
        isDetached: Boolean = false,
    ): CoseSign1 = signing.sign1(payload = payload, signer = signer, externalAad = externalAad, isDetached = isDetached)

    /**
     * Signs [payload] as a COSE_Sign by every one of [signers].
     *
     * @param payload the content.
     * @param signers the signers, at least one.
     * @param protectedHeaders the protected header parameters of the message.
     * @param unprotectedHeaders the unprotected header parameters of the message.
     * @param externalAad data every signature covers that travels apart; none by default.
     * @param isDetached whether the payload is left out of the message.
     * @return the message.
     * @throws IllegalArgumentException if there is no signer or a header label is in both buckets.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm or a key.
     * @since 1.0.0
     */
    public suspend fun sign(
        payload: ByteString,
        signers: List<CoseSigner>,
        protectedHeaders: CoseHeaders = CoseHeaders.Empty,
        unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
        externalAad: ByteString = ByteString(),
        isDetached: Boolean = false,
    ): CoseSign {
        val body = Layer(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            externalAad = externalAad,
            isDetached = isDetached,
        ).body()
        return signing.sign(
            payload = payload,
            signers = signers,
            body = body,
            externalAad = externalAad,
            isDetached = isDetached,
        )
    }

    /**
     * Verifies [message] with one of [keys].
     *
     * @param message the message.
     * @param keys the keys to try, with public keys.
     * @param algorithms the signature algorithms accepted.
     * @param externalAad the data the signature covers that travels apart; none by default.
     * @param detachedPayload the payload if the message carries none.
     * @return the payload, or why the message is refused.
     * @since 1.0.0
     */
    public suspend fun verify(
        message: CoseSign1,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
        externalAad: ByteString = ByteString(),
        detachedPayload: ByteString? = null,
    ): Outcome<ByteString, CoseFailure> = CoseException.outcome {
        val request = Request(
            keys = keys,
            algorithms = algorithms,
            externalAad = externalAad,
            detached = detachedPayload,
        )
        signing.verify(message, request)
    }

    /**
     * Verifies [message]: succeeds with the first signature that verifies with one of [keys]. The body-level `crit` is
     * checked first; a signature whose layer is refused is skipped.
     *
     * @param message the message.
     * @param keys the keys to try, with public keys.
     * @param algorithms the signature algorithms accepted.
     * @param externalAad the data the signatures cover that travels apart; none by default.
     * @param detachedPayload the payload if the message carries none.
     * @return the signature that verifies, or the failure of the signature that got furthest.
     * @since 1.0.0
     */
    public suspend fun verify(
        message: CoseSign,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
        externalAad: ByteString = ByteString(),
        detachedPayload: ByteString? = null,
    ): Outcome<CoseSignature, CoseFailure> = CoseException.outcome {
        val request = Request(
            keys = keys,
            algorithms = algorithms,
            externalAad = externalAad,
            detached = detachedPayload,
        )
        signing.verify(message, request)
    }

    /**
     * MACs [payload] as a COSE_Mac0 with the symmetric [key].
     *
     * @param payload the content.
     * @param key the MAC key.
     * @param algorithm the MAC algorithm.
     * @param protectedHeaders the protected header parameters; the algorithm is added.
     * @param unprotectedHeaders the unprotected header parameters; the key id of [key] is added.
     * @param externalAad data the MAC covers that travels apart; none by default.
     * @param isDetached whether the payload is left out of the message.
     * @return the message.
     * @throws IllegalArgumentException if [algorithm] is no MAC, [key] does not fit it or a header label is in both
     *   buckets.
     * @since 1.0.0
     */
    public suspend fun mac0(
        payload: ByteString,
        key: CoseKey,
        algorithm: CoseAlgorithm,
        protectedHeaders: CoseHeaders = CoseHeaders.Empty,
        unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
        externalAad: ByteString = ByteString(),
        isDetached: Boolean = false,
    ): CoseMac0 = macing.mac0(
        payload = payload,
        key = key,
        algorithm = algorithm,
        layer = Layer(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            externalAad = externalAad,
            isDetached = isDetached,
        ),
    )

    /**
     * MACs [payload] as a COSE_Mac with a content key that reaches every one of [recipients].
     *
     * @param payload the content.
     * @param algorithm the MAC algorithm.
     * @param recipients the recipients, at least one; a direct recipient is the only one.
     * @param protectedHeaders the protected header parameters; the algorithm is added.
     * @param unprotectedHeaders the unprotected header parameters.
     * @param externalAad data the MAC covers that travels apart; none by default.
     * @param isDetached whether the payload is left out of the message.
     * @return the message.
     * @throws IllegalArgumentException if [algorithm] is no MAC, the recipients do not fit or a header label is in
     *   both buckets.
     * @since 1.0.0
     */
    public suspend fun mac(
        payload: ByteString,
        algorithm: CoseAlgorithm,
        recipients: List<CoseRecipientSpec>,
        protectedHeaders: CoseHeaders = CoseHeaders.Empty,
        unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
        externalAad: ByteString = ByteString(),
        isDetached: Boolean = false,
    ): CoseMac = macing.mac(
        payload = payload,
        algorithm = algorithm,
        specs = recipients,
        layer = Layer(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            externalAad = externalAad,
            isDetached = isDetached,
        ),
    )

    /**
     * Verifies the MAC of [message] with one of the symmetric [keys].
     *
     * @param message the message.
     * @param keys the keys to try.
     * @param algorithms the MAC algorithms accepted.
     * @param externalAad the data the MAC covers that travels apart; none by default.
     * @param detachedPayload the payload if the message carries none.
     * @return the payload, or why the message is refused.
     * @since 1.0.0
     */
    public suspend fun verify(
        message: CoseMac0,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
        externalAad: ByteString = ByteString(),
        detachedPayload: ByteString? = null,
    ): Outcome<ByteString, CoseFailure> = CoseException.outcome {
        val request = Request(
            keys = keys,
            algorithms = algorithms,
            externalAad = externalAad,
            detached = detachedPayload,
        )
        macing.verify(message, request)
    }

    /**
     * Verifies the MAC of [message] with a content key that one of [keys] obtains from a recipient.
     *
     * @param message the message.
     * @param keys the keys of the recipient to try.
     * @param algorithms the MAC and key distribution algorithms accepted.
     * @param externalAad the data the MAC covers that travels apart; none by default.
     * @param detachedPayload the payload if the message carries none.
     * @return the payload, or why the message is refused.
     * @since 1.0.0
     */
    public suspend fun verify(
        message: CoseMac,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
        externalAad: ByteString = ByteString(),
        detachedPayload: ByteString? = null,
    ): Outcome<ByteString, CoseFailure> = CoseException.outcome {
        val request = Request(
            keys = keys,
            algorithms = algorithms,
            externalAad = externalAad,
            detached = detachedPayload,
        )
        macing.verify(message, request)
    }

    /**
     * Encrypts [plaintext] as a COSE_Encrypt0 with the symmetric [key] and a fresh IV, unless the headers carry an IV
     * or a Partial IV, which a base IV of [key] completes.
     *
     * @param plaintext the content.
     * @param key the content key.
     * @param algorithm the content encryption algorithm.
     * @param protectedHeaders the protected header parameters; the algorithm is added.
     * @param unprotectedHeaders the unprotected header parameters; the key id of [key] and the IV are added.
     * @param externalAad data the encryption authenticates that travels apart; none by default.
     * @param isDetached whether the ciphertext is left out of the message.
     * @return the message.
     * @throws IllegalArgumentException if [algorithm] encrypts nothing, [key] does not fit it, a Partial IV has no
     *   base IV or a header label is in both buckets.
     * @since 1.0.0
     */
    public suspend fun encrypt0(
        plaintext: ByteString,
        key: CoseKey,
        algorithm: CoseAlgorithm,
        protectedHeaders: CoseHeaders = CoseHeaders.Empty,
        unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
        externalAad: ByteString = ByteString(),
        isDetached: Boolean = false,
    ): CoseEncrypt0 = encrypting.encrypt0(
        plaintext = plaintext,
        key = key,
        algorithm = algorithm,
        layer = Layer(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            externalAad = externalAad,
            isDetached = isDetached,
        ),
    )

    /**
     * Encrypts [plaintext] as a COSE_Encrypt with a content key that reaches every one of [recipients].
     *
     * @param plaintext the content.
     * @param algorithm the content encryption algorithm.
     * @param recipients the recipients, at least one; a direct recipient is the only one.
     * @param protectedHeaders the protected header parameters; the algorithm is added.
     * @param unprotectedHeaders the unprotected header parameters; a fresh IV is added unless one is given.
     * @param externalAad data the encryption authenticates that travels apart; none by default.
     * @param isDetached whether the ciphertext is left out of the message.
     * @return the message.
     * @throws IllegalArgumentException if [algorithm] encrypts nothing, the recipients do not fit, the headers carry a
     *   Partial IV or a header label is in both buckets.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        plaintext: ByteString,
        algorithm: CoseAlgorithm,
        recipients: List<CoseRecipientSpec>,
        protectedHeaders: CoseHeaders = CoseHeaders.Empty,
        unprotectedHeaders: CoseHeaders = CoseHeaders.Empty,
        externalAad: ByteString = ByteString(),
        isDetached: Boolean = false,
    ): CoseEncrypt = encrypting.encrypt(
        plaintext = plaintext,
        algorithm = algorithm,
        specs = recipients,
        layer = Layer(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            externalAad = externalAad,
            isDetached = isDetached,
        ),
    )

    /**
     * Decrypts [message] with one of the symmetric [keys].
     *
     * @param message the message.
     * @param keys the keys to try.
     * @param algorithms the content encryption algorithms accepted.
     * @param externalAad the data the encryption authenticates that travels apart; none by default.
     * @param detachedCiphertext the ciphertext if the message carries none.
     * @return the plaintext, or why the message is refused: [CoseFailure.DecryptionFailed] for every wrong key or tag.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        message: CoseEncrypt0,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
        externalAad: ByteString = ByteString(),
        detachedCiphertext: ByteString? = null,
    ): Outcome<ByteString, CoseFailure> = CoseException.outcome {
        val request = Request(
            keys = keys,
            algorithms = algorithms,
            externalAad = externalAad,
            detached = detachedCiphertext,
        )
        encrypting.decrypt(message, request)
    }

    /**
     * Decrypts [message] with a content key that one of [keys] obtains from a recipient.
     *
     * @param message the message.
     * @param keys the keys of the recipient to try.
     * @param algorithms the content encryption and key distribution algorithms accepted.
     * @param externalAad the data the encryption authenticates that travels apart; none by default.
     * @param detachedCiphertext the ciphertext if the message carries none.
     * @return the plaintext, or why the message is refused: [CoseFailure.DecryptionFailed] for every wrong key, wrapped
     *   key or tag.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        message: CoseEncrypt,
        keys: List<CoseKey>,
        algorithms: Set<CoseAlgorithm>,
        externalAad: ByteString = ByteString(),
        detachedCiphertext: ByteString? = null,
    ): Outcome<ByteString, CoseFailure> = CoseException.outcome {
        val request = Request(
            keys = keys,
            algorithms = algorithms,
            externalAad = externalAad,
            detached = detachedCiphertext,
        )
        encrypting.decrypt(message, request)
    }

    /**
     * Reads the certificates of the `x5chain` parameter of [headers] with the limits of X.509. The chain is not
     * validated; run the path validation of krypt-x509 before trusting its end-entity key.
     *
     * @param headers the header parameters, usually of the layer that names the key.
     * @return the certificates, the end-entity certificate first, or [CoseFailure.Malformed] if one is broken.
     * @since 1.0.0
     */
    public fun certificateChain(headers: CoseHeaders): Outcome<List<Certificate>, CoseFailure> = CoseException.outcome {
        headers.certificateChain.map { encoded ->
            present(certificates.decode(encoded).getOrNull(), CoseFailure.Malformed)
        }
    }

    /**
     * Returns the `x5t` hash of [certificate].
     *
     * @param certificate the certificate.
     * @param digest SHA-256 by default, SHA-384 or SHA-512.
     * @return the hash.
     * @throws IllegalArgumentException if COSE names no certificate hash for [digest] in krypt.
     * @since 1.0.0
     */
    public suspend fun certificateHash(
        certificate: Certificate,
        digest: DigestAlgorithm = DigestAlgorithm.Sha256,
    ): CoseCertificateHash {
        val algorithm = CoseCertificateHash.idOf(digest)
        return CoseCertificateHash(algorithm = algorithm, value = crypto.digests.digest(certificate.encoded, digest))
    }

    /**
     * Tells whether [hash] is the `x5t` of [certificate].
     *
     * @param hash the hash, possibly from an attacker.
     * @param certificate the certificate.
     * @return true if the hash names a digest krypt computes and matches the certificate.
     * @since 1.0.0
     */
    public suspend fun matches(hash: CoseCertificateHash, certificate: Certificate): Boolean {
        val digest = hash.digest ?: return false
        return crypto.digests.digest(certificate.encoded, digest) == hash.value
    }

    /**
     * Shows the limits, the mode and the labels the application processes.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Cose($limits, $mode, criticalLabels=$criticalLabels)"
}
