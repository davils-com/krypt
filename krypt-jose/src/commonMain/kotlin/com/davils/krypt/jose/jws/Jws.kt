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

package com.davils.krypt.jose.jws

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.Base64Url
import com.davils.krypt.jose.internal.HeaderNames
import com.davils.krypt.jose.internal.HeaderRules
import com.davils.krypt.jose.internal.JwsCodec
import com.davils.krypt.jose.internal.JwsCrypto
import com.davils.krypt.jose.internal.JwsVerifier
import com.davils.krypt.jose.internal.SIGNING
import com.davils.krypt.jose.internal.isUsable
import com.davils.krypt.jose.internal.stringsOf
import com.davils.krypt.jose.internal.text
import com.davils.krypt.jose.internal.textOrNull
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.ValidationParameters
import kotlinx.io.bytestring.ByteString

private const val DOT: Byte = '.'.code.toByte()
private const val PAYLOAD: String = "payload"
private const val SIGNATURES: String = "signatures"
private const val SIGNATURE: String = "signature"
private const val PROTECTED: String = "protected"
private const val HEADER: String = "header"

/**
 * JSON Web Signatures of RFC 7515: the compact and the JSON serialization, general and flattened, detached
 * payloads of Appendix F and unencoded payloads of RFC 7797.
 *
 * Verification follows RFC 8725: the caller names the acceptable algorithms and the keys; `alg` alone never decides,
 * `none` is unknown, a key is only tried for an algorithm it fits (an HMAC key of at least the size of the hash, an
 * RSA key for RS and PS, an EC key on the curve of the ES algorithm, an Ed25519 or Ed448 key for EdDSA), a `crit`
 * entry krypt or the caller does not understand is refused, and keys a header carries itself are never trusted. The
 * crypto policy of the environment is asked by every operation; when it refuses, verification gives
 * [JoseFailure.AlgorithmNotAllowed].
 *
 * The object holds no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto of the signatures.
 * @property limits the limits of decoding.
 * @since 1.0.0
 */
public class Jws(public val crypto: Crypto, public val limits: JoseLimits = JoseLimits.Default) {
    private val signatures = JwsCrypto(crypto)
    private val codec = JwsCodec(limits)
    private val verifier = JwsVerifier(signatures)
    private val certificates = Certificates(crypto)

    /**
     * Signs [payload] in the compact serialization.
     *
     * @param payload the payload.
     * @param signer the key, the algorithm and the header; its unprotected header must be empty.
     * @param isDetached whether to leave the payload out, as in Appendix F of RFC 7515.
     * @param isPayloadEncoded false for an unencoded payload of RFC 7797, which adds `b64` and `crit`; an attached
     *   unencoded payload must be UTF-8 text without a period.
     * @return the compact serialization.
     * @throws IllegalArgumentException if the key does not fit the algorithm, the header sets `alg` or `b64`, or the
     *   payload cannot be carried as asked.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun sign(
        payload: ByteString,
        signer: JwsSigner,
        isDetached: Boolean = false,
        isPayloadEncoded: Boolean = true,
    ): String {
        require(signer.unprotectedHeader.members.isEmpty()) { "The compact serialization has no unprotected header" }
        val part = payloadPart(payload = payload, isEncoded = isPayloadEncoded, isDetached = isDetached)
        require(isPayloadEncoded || '.' !in part) { "An unencoded compact payload holds no period" }
        val (protected, signature) = signOne(signer = signer, payload = payload, isEncoded = isPayloadEncoded)
        return "$protected.$part.${Base64Url.encode(signature)}"
    }

    /**
     * Signs [payload] in the JSON serialization.
     *
     * @param payload the payload.
     * @param signers the signatures to make, at least one; exactly one if [isFlattened].
     * @param isFlattened whether to write the flattened form.
     * @param isDetached whether to leave the payload out.
     * @param isPayloadEncoded false for an unencoded payload of RFC 7797; an attached unencoded payload must be UTF-8.
     * @return the JSON serialization.
     * @throws IllegalArgumentException if a key does not fit its algorithm, a header sets `alg` or `b64`, the
     *   protected and the unprotected header share a member, or the number of signers is wrong.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm or a key.
     * @since 1.0.0
     */
    public suspend fun signJson(
        payload: ByteString,
        signers: List<JwsSigner>,
        isFlattened: Boolean = false,
        isDetached: Boolean = false,
        isPayloadEncoded: Boolean = true,
    ): String {
        require(signers.isNotEmpty() && (!isFlattened || signers.size == 1)) { "A flattened JWS has one signature" }
        val part = payloadPart(payload = payload, isEncoded = isPayloadEncoded, isDetached = isDetached)
        val entries = signers.map { signer ->
            entryOf(signer = signer, payload = payload, isEncoded = isPayloadEncoded)
        }
        val payloadMembers = listOfNotNull((PAYLOAD to text(part)).takeUnless { isDetached })
        val members = when (isFlattened) {
            true -> payloadMembers + entries.single().members
            false -> payloadMembers + (SIGNATURES to JsonValue.Array(entries))
        }
        return JsonValue.Object(members).encode()
    }

    /**
     * Reads a JWS in the compact or the JSON serialization, without verifying it.
     *
     * The headers must be JSON objects within [limits], every member of a known name must have its type, protected
     * and unprotected headers share no member, `b64` must be protected and the same for every signature, a `b64` of
     * false must be listed in `crit` as RFC 7797 section 6 asks, and a JSON serialization carries at most
     * [JoseLimits.maximumRecipients] signatures.
     *
     * @param text the serialization, possibly from an attacker.
     * @return the message, or why it was refused.
     * @since 1.0.0
     */
    public fun decode(text: String): Outcome<JwsMessage, JoseFailure> = codec.decode(text)

    /**
     * Verifies [message] with [keys]. The first signature that verifies with an algorithm of [algorithms] and a
     * fitting key wins; if none does, the failure of the first signature is returned.
     *
     * @param message the decoded message.
     * @param keys the keys to try: public keys and HMAC keys; a key with a key id is only tried for a matching `kid`.
     * @param algorithms the acceptable algorithms.
     * @param detachedPayload the payload of a message whose payload is detached, or null.
     * @param critical the `crit` extensions the caller understands and processes itself, besides `b64`.
     * @return the verified message, or why it does not verify.
     * @since 1.0.0
     */
    public suspend fun verify(
        message: JwsMessage,
        keys: List<JoseKey>,
        algorithms: Set<JwsAlgorithm>,
        detachedPayload: ByteString? = null,
        critical: Set<String> = emptySet(),
    ): Outcome<VerifiedJws, JoseFailure> = verifier.verify(
        message = message,
        algorithms = algorithms,
        detached = detachedPayload,
        critical = critical,
    ) { _ -> Outcome.Success(keys) }

    /**
     * Reads and verifies [text]; see [decode] and the other [verify].
     *
     * @param text the serialization, possibly from an attacker.
     * @param keys the keys to try.
     * @param algorithms the acceptable algorithms.
     * @param detachedPayload the payload of a message whose payload is detached, or null.
     * @param critical the `crit` extensions the caller understands, besides `b64`.
     * @return the verified message, or why it was refused.
     * @since 1.0.0
     */
    public suspend fun verify(
        text: String,
        keys: List<JoseKey>,
        algorithms: Set<JwsAlgorithm>,
        detachedPayload: ByteString? = null,
        critical: Set<String> = emptySet(),
    ): Outcome<VerifiedJws, JoseFailure> = decode(text).flatMap { message ->
        verify(
            message = message,
            keys = keys,
            algorithms = algorithms,
            detachedPayload = detachedPayload,
            critical = critical,
        )
    }

    /**
     * Verifies [message] with the key of its `x5c` chain, after [validator] validated the chain by RFC 5280. A
     * signature without `x5c` gives [JoseFailure.UntrustedCertificate], as does a chain that does not validate; a
     * chain longer than [JoseLimits.maximumCertificates] gives [JoseFailure.LimitExceeded] before any certificate is
     * decoded.
     *
     * @param message the decoded message.
     * @param validator the path validator with the trust anchors of the caller.
     * @param algorithms the acceptable algorithms.
     * @param parameters the parameters of the path validation.
     * @param detachedPayload the payload of a message whose payload is detached, or null.
     * @param critical the `crit` extensions the caller understands, besides `b64`.
     * @return the verified message, whose key is the one of the first certificate, or why it was refused.
     * @since 1.0.0
     */
    public suspend fun verifyWithChain(
        message: JwsMessage,
        validator: PathValidator,
        algorithms: Set<JwsAlgorithm>,
        parameters: ValidationParameters = ValidationParameters(),
        detachedPayload: ByteString? = null,
        critical: Set<String> = emptySet(),
    ): Outcome<VerifiedJws, JoseFailure> = verifier.verify(
        message = message,
        algorithms = algorithms,
        detached = detachedPayload,
        critical = critical,
    ) { signature -> chainKeys(signature = signature, validator = validator, parameters = parameters) }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Jws($limits)"

    private suspend fun chainKeys(
        signature: JwsSignature,
        validator: PathValidator,
        parameters: ValidationParameters,
    ): Outcome<List<JoseKey>, JoseFailure> {
        val header = signature.header.members
        val encoded = header.stringsOf(HeaderNames.CHAIN).orEmpty()
        val countFailure = JoseFailure.UntrustedCertificate.takeIf { encoded.isEmpty() }
            ?: JoseFailure.LimitExceeded.takeIf { encoded.size > limits.maximumCertificates }
        val counted = encoded.takeIf { countFailure == null }.orEmpty()
        val chain = counted.mapNotNull { text ->
            Base64Url.decodeStandard(text)?.let { der -> certificates.decode(der).getOrNull() }
        }
        val failure = countFailure ?: JoseFailure.Malformed.takeIf { chain.size != encoded.size }
        if (failure != null) return Outcome.Failure(failure)
        return validated(chain = chain, validator = validator, parameters = parameters)
    }

    private suspend fun validated(
        chain: List<Certificate>,
        validator: PathValidator,
        parameters: ValidationParameters,
    ): Outcome<List<JoseKey>, JoseFailure> {
        val leaf = chain.first()
        val validation = validator.validate(leaf = leaf, intermediates = chain.drop(1), parameters = parameters)
        val publicKey = leaf.publicKey?.takeIf { validation.isValid }
        val keys = publicKey?.let { found -> listOf<JoseKey>(JoseKey.Public(found)) }
        return keys?.let { found -> Outcome.Success(found) } ?: Outcome.Failure(JoseFailure.UntrustedCertificate)
    }

    private suspend fun entryOf(signer: JwsSigner, payload: ByteString, isEncoded: Boolean): JsonValue.Object {
        val (protected, signature) = signOne(signer = signer, payload = payload, isEncoded = isEncoded)
        val unprotected = signer.unprotectedHeader
        val members = listOf(PROTECTED to text(protected)) +
            listOfNotNull((HEADER to unprotected).takeIf { unprotected.members.isNotEmpty() }) +
            (SIGNATURE to text(Base64Url.encode(signature)))
        return JsonValue.Object(members)
    }

    private suspend fun signOne(signer: JwsSigner, payload: ByteString, isEncoded: Boolean): Pair<String, ByteString> {
        val name = signer.algorithm.algorithmName
        require(isUsable(signer.key, SIGNING, setOf(name))) { "The key is not for $name" }
        val header = protectedOf(signer = signer, isEncoded = isEncoded).encode()
        val protected = Base64Url.encode(header.encodeToByteArray())
        val payloadInput = when (isEncoded) {
            true -> Base64Url.encode(payload).encodeToByteArray()
            false -> payload.toByteArray()
        }
        val input = ByteString(protected.encodeToByteArray() + DOT + payloadInput)
        return protected to signatures.sign(algorithm = signer.algorithm, key = signer.key, input = input)
    }

    private fun protectedOf(signer: JwsSigner, isEncoded: Boolean): JsonValue.Object {
        val header = signer.header
        val unprotected = signer.unprotectedHeader
        require(HeaderNames.ALGORITHM !in header && HeaderNames.BASE64 !in header) { "Jws writes alg and b64" }
        require(isEncoded || HeaderNames.CRITICAL !in header) { "Jws writes crit of an unencoded payload" }
        require(OWN.none { name -> name in unprotected }) { "alg, b64 and crit are protected" }
        val isKeyIdNamed = HeaderNames.KEY_ID in header || HeaderNames.KEY_ID in unprotected
        val keyId = signer.key.keyId?.takeUnless { isKeyIdNamed }
        val members = listOf(HeaderNames.ALGORITHM to text(signer.algorithm.algorithmName)) +
            header.members +
            listOfNotNull(keyId?.let { found -> HeaderNames.KEY_ID to text(found) }) +
            unencodedMembers(isEncoded)
        val protected = JsonValue.Object(members)
        require(protected.names.none { name -> name in unprotected }) { "The headers share a member" }
        HeaderRules.checkTypes(protected)
        HeaderRules.checkTypes(unprotected)
        return protected
    }

    private fun unencodedMembers(isEncoded: Boolean): List<Pair<String, JsonValue>> = when (isEncoded) {
        true -> emptyList()

        false -> listOf(
            HeaderNames.BASE64 to JsonValue.Bool(false),
            HeaderNames.CRITICAL to JsonValue.Array(listOf(text(HeaderNames.BASE64))),
        )
    }

    private fun payloadPart(payload: ByteString, isEncoded: Boolean, isDetached: Boolean): String {
        if (isDetached) return ""
        return when (isEncoded) {
            true -> Base64Url.encode(payload)
            false -> requireNotNull(textOrNull(payload.toByteArray())) { "An unencoded payload is UTF-8 text" }
        }
    }

    private companion object {
        val OWN: List<String> = listOf(HeaderNames.ALGORITHM, HeaderNames.BASE64, HeaderNames.CRITICAL)
    }
}
