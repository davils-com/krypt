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

package com.davils.krypt.jose.jwt

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.ClaimsCheck
import com.davils.krypt.jose.internal.HeaderNames
import com.davils.krypt.jose.internal.HeaderReader
import com.davils.krypt.jose.internal.checkClaims
import com.davils.krypt.jose.internal.decoding
import com.davils.krypt.jose.internal.textOrNull
import com.davils.krypt.jose.jwe.DecryptedJwe
import com.davils.krypt.jose.jwe.Jwe
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsMessage
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val SIGNED_DOTS: Int = 2
private const val ENCRYPTED_DOTS: Int = 4
private val COMPACT_ALPHABET: Set<Char> = (('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '_', '.')).toSet()

/**
 * JSON Web Tokens of RFC 7519, signed, encrypted or both (nested), and validated by the best current practice of
 * RFC 8725.
 *
 * A token is always in the compact serialization. [validate] verifies the signature with the algorithms and keys of
 * the caller, never with a key the token carries, refuses an unencoded payload, decrypts an encrypted token first and
 * demands a signed token inside unless the validator waives it, checks the explicit type, then the required claims,
 * the times against [com.davils.krypt.core.Environment.clock] with the skew of the validator, the issuer and the
 * audience. Every failure is a [JoseFailure]; no input makes it throw.
 *
 * The object holds no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto of the signatures and the encryption.
 * @property limits the limits of decoding.
 * @since 1.0.0
 */
public class Jwt(public val crypto: Crypto, public val limits: JoseLimits = JoseLimits.Default) {
    private val jws = Jws(crypto, limits)
    private val jwe = Jwe(crypto, limits)
    private val headers = HeaderReader(limits)

    /**
     * Signs [claims] as a JWS in the compact serialization.
     *
     * @param claims the claims.
     * @param key the private key or the HMAC key.
     * @param algorithm the signature algorithm.
     * @param type the `typ` header, `JWT` by default; an explicit type such as `at+jwt` lets a validator tell tokens
     *   of different kinds apart; null for none.
     * @param header further members of the protected header.
     * @return the token.
     * @throws IllegalArgumentException if the key does not fit the algorithm or the header sets `alg`, `b64` or `typ`
     *   twice.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun sign(
        claims: JwtClaims,
        key: JoseKey,
        algorithm: JwsAlgorithm,
        type: String? = DEFAULT_TYPE,
        header: JsonValue.Object = JsonValue.Object.Empty,
    ): String = jws.sign(
        payload = ByteString(claims.encode().encodeToByteArray()),
        signer = JwsSigner(key = key, algorithm = algorithm, header = typed(type, header)),
    )

    /**
     * Encrypts [claims] as a JWE in the compact serialization, without a signature. Only a validator with
     * [JwtValidator.isSignatureRequired] false accepts it; prefer [signAndEncrypt].
     *
     * @param claims the claims.
     * @param recipient the recipient.
     * @param encryption the content encryption.
     * @param type the `typ` header, `JWT` by default, or null.
     * @return the token.
     * @throws IllegalArgumentException if the key does not fit the algorithm.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        claims: JwtClaims,
        recipient: JweRecipient,
        encryption: JweEncryption,
        type: String? = DEFAULT_TYPE,
    ): String = jwe.encrypt(
        plaintext = ByteString(claims.encode().encodeToByteArray()),
        recipient = recipient,
        encryption = encryption,
        header = typed(type, JsonValue.Object.Empty),
    )

    /**
     * Signs [claims] and encrypts the signed token as a nested JWT, whose JWE carries the `cty` `JWT`.
     *
     * @param claims the claims.
     * @param key the private key or the HMAC key of the signature.
     * @param algorithm the signature algorithm.
     * @param recipient the recipient of the encryption.
     * @param encryption the content encryption.
     * @param type the `typ` header of the signed token, `JWT` by default, or null.
     * @return the token.
     * @throws IllegalArgumentException if a key does not fit its algorithm.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm or a key.
     * @since 1.0.0
     */
    public suspend fun signAndEncrypt(
        claims: JwtClaims,
        key: JoseKey,
        algorithm: JwsAlgorithm,
        recipient: JweRecipient,
        encryption: JweEncryption,
        type: String? = DEFAULT_TYPE,
    ): String {
        val signed = sign(claims = claims, key = key, algorithm = algorithm, type = type)
        return jwe.encrypt(
            plaintext = ByteString(signed.encodeToByteArray()),
            recipient = recipient,
            encryption = encryption,
            header = JsonValue.Object.of(HeaderNames.CONTENT_TYPE to JsonValue.Text(DEFAULT_TYPE)),
        )
    }

    /**
     * Validates [token] with [validator].
     *
     * A JWT is always in the compact serialization (RFC 7519 section 1): a token with any character outside the
     * Base64url alphabet and the dots, or with other than two or four dots, is refused with [JoseFailure.Malformed]
     * before anything is decoded, so a JWE in the JSON serialization never reaches validation with headers that no
     * tag covers. `typ` and `cty` are read from the protected header only.
     *
     * @param token the token in the compact serialization, possibly from an attacker.
     * @param validator the checks.
     * @param keys the keys that may verify the signature.
     * @param decryptionKeys the keys that may decrypt an encrypted token.
     * @return the token, or the first check it failed.
     * @since 1.0.0
     */
    public suspend fun validate(
        token: String,
        validator: JwtValidator,
        keys: List<JoseKey>,
        decryptionKeys: List<JoseKey> = emptyList(),
    ): Outcome<ValidatedJwt, JoseFailure> {
        val dots = token.count { char -> char == '.' }
        val isShaped = dots == SIGNED_DOTS || dots == ENCRYPTED_DOTS
        val isCompact = isShaped && token.all { char -> char in COMPACT_ALPHABET }
        if (!isCompact) return Outcome.Failure(JoseFailure.Malformed)
        return when (dots == ENCRYPTED_DOTS) {
            true -> encrypted(token = token, validator = validator, keys = keys, decryptionKeys = decryptionKeys)
            false -> signed(token = token, validator = validator, keys = keys, isEncrypted = false)
        }
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Jwt($limits)"

    private suspend fun encrypted(
        token: String,
        validator: JwtValidator,
        keys: List<JoseKey>,
        decryptionKeys: List<JoseKey>,
    ): Outcome<ValidatedJwt, JoseFailure> = jwe.decode(token).flatMap { message ->
        val decryption = jwe.decrypt(
            message = message,
            keys = decryptionKeys,
            algorithms = validator.keyAlgorithms,
            encryptions = validator.encryptions,
            critical = validator.critical,
        )
        val protectedHeader = JoseHeader(message.protectedHeader)
        decryption.flatMap { decrypted ->
            val isNested = protectedHeader.contentType.equals(DEFAULT_TYPE, ignoreCase = true)
            when (isNested) {
                true -> nested(decrypted = decrypted, validator = validator, keys = keys)
                false -> unsigned(decrypted = decrypted, header = protectedHeader, validator = validator)
            }
        }
    }

    private suspend fun nested(
        decrypted: DecryptedJwe,
        validator: JwtValidator,
        keys: List<JoseKey>,
    ): Outcome<ValidatedJwt, JoseFailure> {
        val inner = textOrNull(decrypted.plaintext.toByteArray())
        val token = inner?.takeIf { text -> text.count { char -> char == '.' } == SIGNED_DOTS }
            ?: return Outcome.Failure(JoseFailure.Malformed)
        return signed(token = token, validator = validator, keys = keys, isEncrypted = true)
    }

    private fun unsigned(
        decrypted: DecryptedJwe,
        header: JoseHeader,
        validator: JwtValidator,
    ): Outcome<ValidatedJwt, JoseFailure> {
        if (validator.isSignatureRequired) return Outcome.Failure(JoseFailure.SignatureRequired)
        return finish(
            payload = decrypted.plaintext,
            header = header,
            algorithm = null,
            key = decrypted.key,
            validator = validator,
        )
    }

    private suspend fun signed(
        token: String,
        validator: JwtValidator,
        keys: List<JoseKey>,
        isEncrypted: Boolean,
    ): Outcome<ValidatedJwt, JoseFailure> {
        val decoded = jws.decode(token)
        val verification = decoded.flatMap { message ->
            verified(message = message, validator = validator, keys = keys)
        }
        return verification.flatMap { verified ->
            finish(
                payload = verified.payload,
                header = verified.header,
                algorithm = verified.algorithm,
                key = verified.key,
                validator = validator,
                isEncrypted = isEncrypted,
            )
        }
    }

    private suspend fun verified(message: JwsMessage, validator: JwtValidator, keys: List<JoseKey>) =
        when (message.isCompact && message.isPayloadEncoded) {
            true -> jws.verify(
                message = message,
                keys = keys,
                algorithms = validator.algorithms,
                critical = validator.critical,
            )

            false -> Outcome.Failure(JoseFailure.Malformed)
        }

    private fun finish(
        payload: ByteString,
        header: JoseHeader,
        algorithm: JwsAlgorithm?,
        key: JoseKey,
        validator: JwtValidator,
        isEncrypted: Boolean = true,
    ): Outcome<ValidatedJwt, JoseFailure> = decoding {
        val json = headers.objectOf(payload.toByteArray())
        checkClaims(json)
        JwtClaims(json)
    }.flatMap { claims ->
        val now = crypto.environment.clock.now()
        val failure = ClaimsCheck.typeFailure(expected = validator.type, actual = header.type)
            ?: ClaimsCheck.claimsFailure(claims = claims, validator = validator, now = now)
        val validated = ValidatedJwt(
            claims = claims,
            header = header,
            algorithm = algorithm,
            key = key,
            isEncrypted = isEncrypted,
        )
        failure?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(validated)
    }

    private fun typed(type: String?, header: JsonValue.Object): JsonValue.Object {
        val typeMember = type?.let { found -> HeaderNames.TYPE to JsonValue.Text(found) }
        return JsonValue.Object(listOfNotNull(typeMember) + header.members)
    }

    private companion object {
        const val DEFAULT_TYPE: String = "JWT"
    }
}
