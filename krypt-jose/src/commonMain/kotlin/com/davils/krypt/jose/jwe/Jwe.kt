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

package com.davils.krypt.jose.jwe

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseHeader
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.Attempt
import com.davils.krypt.jose.internal.Base64Url
import com.davils.krypt.jose.internal.ContentCipher
import com.davils.krypt.jose.internal.HeaderNames
import com.davils.krypt.jose.internal.HeaderRules
import com.davils.krypt.jose.internal.JweCodec
import com.davils.krypt.jose.internal.KeyManagement
import com.davils.krypt.jose.internal.RecipientParts
import com.davils.krypt.jose.internal.Unwrapped
import com.davils.krypt.jose.internal.decoding
import com.davils.krypt.jose.internal.invariant
import com.davils.krypt.jose.internal.merged
import com.davils.krypt.jose.internal.requireDisjoint
import com.davils.krypt.jose.internal.text
import com.davils.krypt.jose.internal.textOf
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import kotlinx.io.bytestring.ByteString

/**
 * JSON Web Encryption of RFC 7516 with the algorithms of RFC 7518 and RFC 8037: the compact and the JSON
 * serialization, general and flattened, with one or several recipients.
 *
 * Decryption follows RFC 8725: the caller names the acceptable key management algorithms and content encryptions and
 * the keys; `zip` is refused, a `crit` entry the caller does not understand is refused, a message has at most
 * [JoseLimits.maximumRecipients] recipients and PBES2 at most [JoseLimits.maximumIterations] iterations within the
 * bounds of the crypto policy, checked before any work. A message with more than [MAXIMUM_PASSWORD_RECIPIENTS]
 * PBES2 recipients is refused, and each password key derives at most once per message: it is tried with the first
 * PBES2 recipient whose `kid` it fits and skipped for the others. The worst case of one decryption is therefore one
 * PBKDF2 derivation of [JoseLimits.maximumIterations] iterations per password key, whatever the number of
 * recipients; give several password keys only when you accept that cost. A wrong key, a wrong tag and a wrong
 * padding all give [JoseFailure.DecryptionFailed]: when a content key cannot be recovered, a random one takes its
 * place, so the failure only shows at the tag, as RFC 7516 recommends. With AES-CBC and HMAC the tag is checked in
 * constant time before anything is decrypted.
 *
 * PBES2 with a password is only possible when [isPasswordAllowed] is set; a password is a weak key.
 *
 * The object holds no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto of the encryption.
 * @property limits the limits of decoding.
 * @property isPasswordAllowed whether PBES2 may be used to encrypt and decrypt.
 * @since 1.0.0
 */
public class Jwe(
    public val crypto: Crypto,
    public val limits: JoseLimits = JoseLimits.Default,
    public val isPasswordAllowed: Boolean = false,
) {
    private val codec = JweCodec(limits)
    private val content = ContentCipher(crypto)
    private val management = KeyManagement(crypto = crypto, keys = JsonWebKeys(crypto, limits), limits = limits)

    /**
     * Encrypts [plaintext] to [recipient] in the compact serialization. The protected header holds `alg`, `enc`, the
     * members of [header] and of the recipient, the members the key management generates and the `kid` of the key.
     *
     * @param plaintext the plaintext.
     * @param recipient the recipient.
     * @param encryption the content encryption.
     * @param header further members of the protected header, such as `typ` or `cty`.
     * @return the compact serialization.
     * @throws IllegalArgumentException if the key does not fit the algorithm, a header sets a member krypt writes
     *   itself or `zip`, or PBES2 is used without [isPasswordAllowed].
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        plaintext: ByteString,
        recipient: JweRecipient,
        encryption: JweEncryption,
        header: JsonValue.Object = JsonValue.Object.Empty,
    ): String {
        checkRecipient(recipient)
        checkHeader(header)
        val callerHeader = JsonValue.Object(header.members + recipient.header.members)
        val cek = randomKey(encryption)
        val wrapped = management.encrypt(
            recipient = recipient,
            encryption = encryption,
            cek = cek,
            header = callerHeader,
        )
        val algorithms = listOf(
            HeaderNames.ALGORITHM to text(recipient.algorithm.algorithmName),
            HeaderNames.ENCRYPTION to text(encryption.algorithmName),
        )
        val generated = wrapped.members + keyIdOf(recipient.key, callerHeader)
        val protected = JsonValue.Object(algorithms + callerHeader.members + generated)
        val protectedEncoded = Base64Url.encode(protected.encode().encodeToByteArray())
        val sealed = seal(cek = wrapped.cek, encryption = encryption, plaintext = plaintext, aad = protectedEncoded)
        cek.destroy()
        val encryptedKey = Base64Url.encode(wrapped.encryptedKey)
        val parts = listOf(protectedEncoded, encryptedKey, sealed.iv, sealed.ciphertext, sealed.tag)
        return parts.joinToString(separator = ".")
    }

    /**
     * Encrypts [plaintext] to [recipients] in the JSON serialization. The protected header holds `enc` and the members
     * of [protectedHeader]; every recipient header holds `alg`, the members of the recipient, the members the key
     * management generates and the `kid` of the key.
     *
     * @param plaintext the plaintext.
     * @param recipients the recipients, 1 to [JoseLimits.maximumRecipients]; only one with `dir` or `ECDH-ES`.
     * @param encryption the content encryption.
     * @param protectedHeader further members of the protected header.
     * @param sharedHeader the members of the shared unprotected header.
     * @param additionalData additional authenticated data, or null.
     * @param isFlattened whether to write the flattened form, for exactly one recipient.
     * @return the JSON serialization.
     * @throws IllegalArgumentException if a key does not fit its algorithm, the headers share a member or set one
     *   krypt writes itself, the number of recipients is wrong, or PBES2 is used without [isPasswordAllowed].
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids an algorithm or a key.
     * @since 1.0.0
     */
    public suspend fun encryptJson(
        plaintext: ByteString,
        recipients: List<JweRecipient>,
        encryption: JweEncryption,
        protectedHeader: JsonValue.Object = JsonValue.Object.Empty,
        sharedHeader: JsonValue.Object = JsonValue.Object.Empty,
        additionalData: ByteString? = null,
        isFlattened: Boolean = false,
    ): String {
        val maximum = limits.maximumRecipients
        require(recipients.size in 1..maximum) { "A JWE has 1 to $maximum recipients" }
        require(!isFlattened || recipients.size == 1) { "A flattened JWE has one recipient" }
        require(recipients.size == 1 || recipients.none { recipient -> recipient.algorithm.isDirect }) {
            "dir and ECDH-ES allow only one recipient"
        }
        recipients.forEach { recipient -> checkRecipient(recipient) }
        checkHeader(protectedHeader)
        checkHeader(sharedHeader)
        require(HeaderNames.CRITICAL !in sharedHeader) { "crit is protected" }
        val protected = JsonValue.Object(
            listOf(HeaderNames.ENCRYPTION to text(encryption.algorithmName)) + protectedHeader.members,
        )
        val cek = randomKey(encryption)
        val entries = recipients.map { recipient ->
            entryOf(recipient = recipient, encryption = encryption, cek = cek, shared = listOf(protected, sharedHeader))
        }
        val protectedEncoded = Base64Url.encode(protected.encode().encodeToByteArray())
        val additionalEncoded = additionalData?.let { bytes -> Base64Url.encode(bytes) }
        val aad = additionalEncoded?.let { found -> "$protectedEncoded.$found" } ?: protectedEncoded
        val sealed = seal(cek = entries.first().first, encryption = encryption, plaintext = plaintext, aad = aad)
        cek.destroy()
        val recipientMembers = when (isFlattened) {
            true -> entries.single().second.members
            false -> listOf(RECIPIENTS to JsonValue.Array(entries.map { entry -> entry.second }))
        }
        val head = listOf(PROTECTED to text(protectedEncoded)) +
            listOfNotNull((SHARED to sharedHeader).takeIf { sharedHeader.members.isNotEmpty() })
        val additional = listOfNotNull(additionalEncoded?.let { found -> ADDITIONAL_DATA to text(found) })
        val content = listOf(IV to text(sealed.iv), CIPHERTEXT to text(sealed.ciphertext), TAG to text(sealed.tag))
        val members = head + recipientMembers + additional + content
        return JsonValue.Object(members).encode()
    }

    /**
     * Reads a JWE in the compact or the JSON serialization, without decrypting it.
     *
     * The headers must be JSON objects within [limits], every member of a known name must have its type, the headers
     * of a recipient share no member and name `alg` and `enc`, and a JSON serialization has at most
     * [JoseLimits.maximumRecipients] recipients.
     *
     * @param text the serialization, possibly from an attacker.
     * @return the message, or why it was refused.
     * @since 1.0.0
     */
    public fun decode(text: String): Outcome<JweMessage, JoseFailure> = codec.decode(text)

    /**
     * Decrypts [message] with [keys]. The first recipient whose content key decrypts the message wins; if none does,
     * [JoseFailure.DecryptionFailed] is returned when a key fitted a recipient, the failure of the first recipient
     * otherwise.
     *
     * @param message the decoded message.
     * @param keys the keys to try: private keys, symmetric keys and, with [isPasswordAllowed], passwords; a key with a
     *   key id is only tried for a matching `kid`, and a password only with the first PBES2 recipient it fits.
     * @param algorithms the acceptable key management algorithms.
     * @param encryptions the acceptable content encryptions.
     * @param critical the `crit` extensions the caller understands and processes itself.
     * @return the plaintext, or why the message was refused.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        message: JweMessage,
        keys: List<JoseKey>,
        algorithms: Set<JweAlgorithm>,
        encryptions: Set<JweEncryption>,
        critical: Set<String> = emptySet(),
    ): Outcome<DecryptedJwe, JoseFailure> {
        val passwordRecipients = message.recipients.count { recipient -> isPasswordRecipient(message, recipient) }
        val isBounded = passwordRecipients <= MAXIMUM_PASSWORD_RECIPIENTS
        if (!isBounded) return Outcome.Failure(JoseFailure.LimitExceeded)
        val requests = message.recipients.map { recipient ->
            Request(
                message = message,
                recipient = recipient,
                keys = keys,
                algorithms = algorithms,
                encryptions = encryptions,
                critical = critical,
            )
        }
        return decryptAny(requests)
    }

    /**
     * Reads and decrypts [text]; see [decode] and the other [decrypt].
     *
     * @param text the serialization, possibly from an attacker.
     * @param keys the keys to try.
     * @param algorithms the acceptable key management algorithms.
     * @param encryptions the acceptable content encryptions.
     * @param critical the `crit` extensions the caller understands.
     * @return the plaintext, or why the message was refused.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        text: String,
        keys: List<JoseKey>,
        algorithms: Set<JweAlgorithm>,
        encryptions: Set<JweEncryption>,
        critical: Set<String> = emptySet(),
    ): Outcome<DecryptedJwe, JoseFailure> = decode(text).flatMap { message ->
        decrypt(message = message, keys = keys, algorithms = algorithms, encryptions = encryptions, critical = critical)
    }

    /**
     * Shows the limits and the opt-in.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Jwe($limits, passwordAllowed=$isPasswordAllowed)"

    private suspend fun decryptAny(requests: List<Request>): Outcome<DecryptedJwe, JoseFailure> {
        val failures = ArrayList<JoseFailure>()
        val derived = ArrayList<JoseKey>()
        for (request in requests) {
            when (val outcome = attempt { decryptFor(request, derived) }) {
                is Outcome.Success -> return outcome
                is Outcome.Failure -> failures += outcome.failure
            }
        }
        val isDecryptionFailed = JoseFailure.DecryptionFailed in failures
        val failure = JoseFailure.DecryptionFailed.takeIf { isDecryptionFailed } ?: failures.first()
        return Outcome.Failure(failure)
    }

    private suspend fun decryptFor(
        request: Request,
        derived: MutableList<JoseKey>,
    ): Outcome<DecryptedJwe, JoseFailure> {
        val message = request.message
        val header = merged(listOf(message.protectedHeader, message.sharedHeader, request.recipient.header))
        val algorithm = JweAlgorithm.of(header.textOf(HeaderNames.ALGORITHM).orEmpty())
        val encryption = JweEncryption.of(header.textOf(HeaderNames.ENCRYPTION).orEmpty())
        val isKnown = HeaderNames.COMPRESSION !in header && algorithm != null && encryption != null
        val isPermitted = algorithm?.kdf == null || isPasswordAllowed
        val isAllowed = algorithm in request.algorithms &&
            encryption in request.encryptions &&
            isPermitted
        val failure = HeaderRules.criticalFailure(
            protected = message.protectedHeader,
            header = header,
            understood = request.critical,
        )
            ?: JoseFailure.UnsupportedAlgorithm.takeUnless { isKnown }
            ?: JoseFailure.AlgorithmNotAllowed.takeUnless { isAllowed }
        if (failure != null) return Outcome.Failure(failure)
        return prepared(
            request = request,
            derived = derived,
            header = header,
            algorithm = invariant(algorithm),
            encryption = invariant(encryption),
        )
    }

    private suspend fun prepared(
        request: Request,
        derived: MutableList<JoseKey>,
        header: JsonValue.Object,
        algorithm: JweAlgorithm,
        encryption: JweEncryption,
    ): Outcome<DecryptedJwe, JoseFailure> {
        val encryptedKey = request.recipient.encryptedKey
        return decoding { management.prepare(algorithm, header, encryptedKey) }.flatMap { parts ->
            val usable = usableKeys(request = request, header = header, algorithm = algorithm, derived = derived)
            val bound = Bound(request = request, header = header, algorithm = algorithm, encryption = encryption)
            withKeys(bound = bound, keys = usable, parts = parts)
        }
    }

    private fun usableKeys(
        request: Request,
        header: JsonValue.Object,
        algorithm: JweAlgorithm,
        derived: MutableList<JoseKey>,
    ): List<JoseKey> {
        val keyId = header.textOf(HeaderNames.KEY_ID)
        val fitting = request.keys.filter { key -> key.keyId == null || keyId == null || key.keyId == keyId }
        if (algorithm.kdf == null) return fitting
        val passwords = fitting.filterIsInstance<JoseKey.Password>().filterNot { key -> key in derived }
        derived += passwords
        return passwords
    }

    private suspend fun withKeys(
        bound: Bound,
        keys: List<JoseKey>,
        parts: RecipientParts,
    ): Outcome<DecryptedJwe, JoseFailure> {
        val request = bound.request
        val algorithm = bound.algorithm
        val encryption = bound.encryption
        var isFitted = false
        var result: DecryptedJwe? = null
        for (key in keys) {
            if (result == null) {
                val attempt = Attempt(
                    algorithm = algorithm,
                    encryption = encryption,
                    key = key,
                    parts = parts,
                    encryptedKey = request.recipient.encryptedKey,
                )
                val unwrapped = management.recover(attempt)
                isFitted = isFitted || unwrapped != null
                val plaintext = unwrapped?.let { found -> open(request.message, encryption, found) }
                result = plaintext?.let { found ->
                    DecryptedJwe(
                        plaintext = found,
                        header = JoseHeader(bound.header),
                        algorithm = algorithm,
                        encryption = encryption,
                        key = key,
                    )
                }
            }
        }
        val failure = when (isFitted) {
            true -> JoseFailure.DecryptionFailed
            false -> JoseFailure.KeyNotFound
        }
        return result?.let { found -> Outcome.Success(found) } ?: Outcome.Failure(failure)
    }

    private fun isPasswordRecipient(message: JweMessage, recipient: EncryptedKey): Boolean {
        val header = merged(listOf(message.protectedHeader, message.sharedHeader, recipient.header))
        val algorithm = JweAlgorithm.of(header.textOf(HeaderNames.ALGORITHM).orEmpty())
        return algorithm?.kdf != null
    }

    private suspend fun open(message: JweMessage, encryption: JweEncryption, unwrapped: Unwrapped): ByteString? {
        val recovered = unwrapped.cek
        val isSized = recovered != null && recovered.size == encryption.keyBytes
        val isShaped = message.iv.size == encryption.ivBytes && message.tag.size == encryption.tagBytes
        if (!isSized || !isShaped) recovered?.destroy()
        if (!isShaped) return null
        val cek = recovered.takeIf { isSized } ?: SecretBytes.random(encryption.keyBytes, crypto.environment.random)
        val aad = message.additionalEncoded?.let { found -> "${message.protectedEncoded}.$found" }
            ?: message.protectedEncoded
        val plaintext = cek.use { key ->
            content.decrypt(
                encryption = encryption,
                cek = key,
                iv = message.iv,
                ciphertext = message.ciphertext,
                tag = message.tag,
                aad = ByteString(aad.encodeToByteArray()),
            )
        }
        return plaintext
    }

    private suspend fun entryOf(
        recipient: JweRecipient,
        encryption: JweEncryption,
        cek: SecretBytes,
        shared: List<JsonValue.Object>,
    ): Pair<SecretBytes, JsonValue.Object> {
        val partial = merged(shared + recipient.header)
        val wrapped = management.encrypt(recipient = recipient, encryption = encryption, cek = cek, header = partial)
        val algorithm = HeaderNames.ALGORITHM to text(recipient.algorithm.algorithmName)
        val generated = wrapped.members + keyIdOf(recipient.key, partial)
        val header = JsonValue.Object(listOf(algorithm) + recipient.header.members + generated)
        requireDisjoint(shared + header)
        val encryptedKey = ENCRYPTED_KEY to text(Base64Url.encode(wrapped.encryptedKey))
        val members = listOf(HEADER to header) + listOfNotNull(encryptedKey.takeUnless { recipient.algorithm.isDirect })
        return wrapped.cek to JsonValue.Object(members)
    }

    private suspend fun seal(cek: SecretBytes, encryption: JweEncryption, plaintext: ByteString, aad: String): Sealed {
        val iv = ByteString(crypto.environment.random.bytes(encryption.ivBytes))
        val (ciphertext, tag) = cek.use { key ->
            content.encrypt(
                encryption = encryption,
                cek = key,
                iv = iv,
                plaintext = plaintext,
                aad = ByteString(aad.encodeToByteArray()),
            )
        }
        return Sealed(
            iv = Base64Url.encode(iv),
            ciphertext = Base64Url.encode(ciphertext),
            tag = Base64Url.encode(tag),
        )
    }

    private fun randomKey(encryption: JweEncryption): SecretBytes =
        SecretBytes.random(size = encryption.keyBytes, random = crypto.environment.random)

    private fun keyIdOf(key: JoseKey, header: JsonValue.Object): List<Pair<String, JsonValue>> {
        val keyId = key.keyId?.takeUnless { HeaderNames.KEY_ID in header }
        return listOfNotNull(keyId?.let { found -> HeaderNames.KEY_ID to text(found) })
    }

    private fun checkRecipient(recipient: JweRecipient) {
        require(recipient.algorithm.kdf == null || isPasswordAllowed) { "PBES2 needs isPasswordAllowed" }
        checkHeader(recipient.header)
        require(HeaderNames.CRITICAL !in recipient.header) { "crit is protected" }
    }

    private fun checkHeader(header: JsonValue.Object) {
        require(GENERATED.none { name -> name in header }) { "krypt writes alg, enc and the key management members" }
    }

    private inline fun attempt(block: () -> Outcome<DecryptedJwe, JoseFailure>): Outcome<DecryptedJwe, JoseFailure> =
        try {
            block()
        } catch (ignored: CryptoException) {
            Outcome.Failure(JoseFailure.AlgorithmNotAllowed)
        }

    private data class Sealed(val iv: String, val ciphertext: String, val tag: String)

    private data class Request(
        val message: JweMessage,
        val recipient: EncryptedKey,
        val keys: List<JoseKey>,
        val algorithms: Set<JweAlgorithm>,
        val encryptions: Set<JweEncryption>,
        val critical: Set<String>,
    )

    private data class Bound(
        val request: Request,
        val header: JsonValue.Object,
        val algorithm: JweAlgorithm,
        val encryption: JweEncryption,
    )

    /**
     * The bound of password recipients.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The most PBES2 recipients a message may have when it is decrypted: 4. A message with more is refused with
         * [JoseFailure.LimitExceeded] before any key is derived.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_PASSWORD_RECIPIENTS: Int = 4

        private const val PROTECTED: String = "protected"
        private const val SHARED: String = "unprotected"
        private const val HEADER: String = "header"
        private const val RECIPIENTS: String = "recipients"
        private const val ENCRYPTED_KEY: String = "encrypted_key"
        private const val ADDITIONAL_DATA: String = "aad"
        private const val IV: String = "iv"
        private const val CIPHERTEXT: String = "ciphertext"
        private const val TAG: String = "tag"
        private val GENERATED: List<String> = listOf(
            HeaderNames.ALGORITHM,
            HeaderNames.ENCRYPTION,
            HeaderNames.COMPRESSION,
            HeaderNames.EPHEMERAL_KEY,
            HeaderNames.IV,
            HeaderNames.TAG,
            HeaderNames.SALT,
            HeaderNames.COUNT,
        )
    }
}
