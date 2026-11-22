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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.keystore.pkcs12

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.keystore.Identities
import com.davils.krypt.keystore.KeystoreFailure
import com.davils.krypt.keystore.KeystoreLimits
import com.davils.krypt.keystore.internal.BagAttributes
import com.davils.krypt.keystore.internal.BagValue
import com.davils.krypt.keystore.internal.KeystoreRefusal
import com.davils.krypt.keystore.internal.MacChecks
import com.davils.krypt.keystore.internal.Pkcs12Oids
import com.davils.krypt.keystore.internal.Pkcs12Reader
import com.davils.krypt.keystore.internal.Pkcs12Writer
import com.davils.krypt.keystore.internal.SafeBag
import com.davils.krypt.keystore.internal.SafeContent
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.cipher.PasswordEncryption
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString

private const val SALT_BYTES: Int = 16
private const val MAC_KEY_BYTES: Int = 32

/**
 * Reads and writes PKCS #12 files (RFC 7292), the key stores of the JDK, OpenSSL and Windows.
 *
 * krypt reads files protected by PBES2 with AES-CBC and PBKDF2 over HMAC-SHA-256 or HMAC-SHA-512, with a classic
 * MAC over SHA-256, SHA-384 or SHA-512 or with PBMAC1 (RFC 9579): what the JDK, OpenSSL 3 and later write by default.
 * The legacy protection of SHA-1, 3DES and RC2 is refused as [KeystoreFailure.Unsupported]. It writes PBES2 with
 * AES-256-CBC and PBMAC1 with HMAC-SHA-256, which the JDK 24 and later and OpenSSL 3.4 and later read.
 *
 * The MAC is checked before anything else is read, so a changed file and a wrong password are both
 * [KeystoreFailure.WrongPassword]. Every iteration count is bounded by the crypto policy or the limits before any
 * work, and the size, the depth and the number of entries are bounded by [limits]. Bags of other types, such as
 * CRLs and secrets, and nested contents are skipped.
 *
 * @property crypto the primitives.
 * @property limits the limits of reading.
 * @constructor Reads and writes with [crypto] within [limits].
 * @since 1.0.0
 */
public class Pkcs12(public val crypto: Crypto, public val limits: KeystoreLimits = KeystoreLimits.Default) {
    private val certificates: Certificates = Certificates(crypto)
    private val derLimits: DerLimits = DerLimits(maximumBytes = limits.maximumBytes)

    /**
     * Reads a PKCS #12 file.
     *
     * Each key is paired with its certificate by the local key id of the file and by proving the pair, and its chain
     * is ordered by name; a key without its certificate is [KeystoreFailure.Malformed]. A certificate that is no
     * certificate of a key and either is marked as trusted or belongs to no chain becomes a [CertificateEntry]; the
     * other certificates of a chain do not, even when they carry a friendly name, as the JDK writes them.
     *
     * @param bytes the file, possibly from an attacker.
     * @param password the password; the same password protects the MAC and every encryption.
     * @return the content, or why it could not be read.
     * @since 1.0.0
     */
    public suspend fun decode(bytes: ByteString, password: SecretText): Outcome<Pkcs12Store, KeystoreFailure> = try {
        Outcome.Success(read(bytes = bytes, password = password))
    } catch (refusal: KeystoreRefusal) {
        Outcome.Failure(refusal.failure)
    } catch (ignored: PolicyViolationException) {
        Outcome.Failure(KeystoreFailure.Refused)
    } catch (ignoredAbsence: UnsupportedAlgorithmException) {
        Outcome.Failure(KeystoreFailure.Unsupported)
    }

    /**
     * Writes a PKCS #12 file.
     *
     * Every private key is encrypted on its own in a shrouded key bag and every certificate in one encrypted
     * content, both with PBES2 and AES-256-CBC; the file is protected by PBMAC1 with HMAC-SHA-256. The certificate of
     * each key carries its alias and a local key id; the rest of its chain follows without attributes.
     *
     * @param store the content.
     * @param password the password, which may not be empty.
     * @param iterations the iterations of PBKDF2; the minimum of the crypto policy by default.
     * @return the file.
     * @throws IllegalArgumentException if [password] is empty.
     * @throws IllegalStateException if a private key is not extractable or was destroyed.
     * @throws PolicyViolationException if the policy forbids [iterations].
     * @since 1.0.0
     */
    public suspend fun encode(
        store: Pkcs12Store,
        password: SecretText,
        iterations: Int = crypto.environment.policy.minimumIterations,
    ): ByteString {
        require(password.length > 0) { "A PKCS #12 file needs a password" }
        val keyBags = mutableListOf<ByteString>()
        val certificateBags = mutableListOf<ByteString>()
        store.keys.forEach { entry ->
            val identity = entry.identity
            val attributes = BagAttributes(friendlyName = entry.alias, localKeyId = localKeyId(identity.certificate))
            val shrouded = crypto.keys.encrypt(key = identity.privateKey, password = password, iterations = iterations)
            keyBags += Pkcs12Writer.bag(type = Pkcs12Oids.SHROUDED_KEY_BAG, value = shrouded, attributes = attributes)
            certificateBags += Pkcs12Writer.certificateBag(identity.certificate.encoded, attributes)
            identity.chain.drop(1).forEach { issuer ->
                certificateBags += Pkcs12Writer.certificateBag(issuer.encoded, BagAttributes())
            }
        }
        store.certificates.forEach { entry ->
            val attributes = BagAttributes(friendlyName = entry.alias, isTrusted = entry.isTrusted)
            certificateBags += Pkcs12Writer.certificateBag(entry.certificate.encoded, attributes)
        }
        val contents = contentsOf(
            keyBags = keyBags,
            certificateBags = certificateBags,
            password = password,
            iterations = iterations,
        )
        val authenticated = Pkcs12Writer.authenticatedSafe(contents)
        return protect(authenticated = authenticated, password = password, iterations = iterations)
    }

    /**
     * Shows the primitives and the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Pkcs12($crypto, $limits)"

    private suspend fun read(bytes: ByteString, password: SecretText): Pkcs12Store {
        KeystoreRefusal.ensure(bytes.size <= limits.maximumBytes, KeystoreFailure.Malformed)
        val pfx = KeystoreRefusal.present(Pkcs12Reader.pfx(bytes, derLimits), KeystoreFailure.Malformed)
        val mac = KeystoreRefusal.present(pfx.mac, KeystoreFailure.Unsupported)
        MacChecks(crypto, password).check(mac = mac, data = pfx.authenticated, limits = limits)
        val read = Pkcs12Reader.contents(pfx.authenticated, derLimits, limits.maximumEntries)
        val contents = KeystoreRefusal.present(read, KeystoreFailure.Malformed)
        val bags = contents.flatMap { content -> bagsOf(content, password) }
        KeystoreRefusal.ensure(bags.size <= limits.maximumEntries, KeystoreFailure.Malformed)
        return assemble(bags = bags, password = password)
    }

    private suspend fun bagsOf(content: SafeContent, password: SecretText): List<SafeBag> {
        val encoded = when (content) {
            is SafeContent.Plain -> content.bags
            is SafeContent.Encrypted -> decrypt(content, password)
            SafeContent.Foreign -> throw KeystoreRefusal(KeystoreFailure.Unsupported)
        }
        val bags = Pkcs12Reader.bags(encoded, derLimits, limits.maximumEntries)
        return KeystoreRefusal.present(bags, KeystoreFailure.Malformed)
    }

    private suspend fun decrypt(content: SafeContent.Encrypted, password: SecretText): ByteString {
        val decrypted = PasswordEncryption.decrypt(
            crypto = crypto,
            algorithm = content.algorithm,
            ciphertext = content.ciphertext,
            password = password,
        )
        return decrypted.orRefuse().use { plaintext -> plaintext.reveal { bytes -> ByteString(bytes) } }
    }

    private suspend fun assemble(bags: List<SafeBag>, password: SecretText): Pkcs12Store {
        val found = bags.mapNotNull { bag -> certificateOf(bag) }
        val keys = bags.mapNotNull { bag ->
            (bag.value as? BagValue.Key)?.let { value ->
                keyEntry(value = value, attributes = bag.attributes, found = found, password = password)
            }
        }
        val leaves = keys.map { entry -> entry.identity.certificate }
        val chained = keys.flatMap { entry -> entry.identity.chain }
        val entries = found.filter { (certificate, attributes) ->
            certificate !in leaves && (attributes.isTrusted || certificate !in chained)
        }
        val certificateEntries = entries.map { (certificate, attributes) ->
            CertificateEntry(
                certificate = certificate,
                alias = attributes.friendlyName,
                isTrusted = attributes.isTrusted,
            )
        }
        return Pkcs12Store(keys = keys, certificates = certificateEntries)
    }

    private fun certificateOf(bag: SafeBag): Pair<Certificate, BagAttributes>? {
        val value = bag.value as? BagValue.Cert ?: return null
        val decoded = certificates.decode(value.encoded).getOrNull()
        val certificate = KeystoreRefusal.present(decoded, KeystoreFailure.Malformed)
        return certificate to bag.attributes
    }

    private suspend fun keyEntry(
        value: BagValue.Key,
        attributes: BagAttributes,
        found: List<Pair<Certificate, BagAttributes>>,
        password: SecretText,
    ): KeyEntry {
        val key = keyOf(value, password)
        val localKeyId = attributes.localKeyId
        val matching = found.filter { (_, other) -> localKeyId != null && other.localKeyId == localKeyId }
        val candidates = (matching + found).map { (certificate, _) -> certificate }
        val formed = Identities(crypto).of(privateKey = key, certificates = candidates)
        val identity = KeystoreRefusal.present(formed.getOrNull(), KeystoreFailure.Malformed)
        return KeyEntry(identity = identity, alias = attributes.friendlyName)
    }

    private suspend fun keyOf(value: BagValue.Key, password: SecretText): PrivateKey {
        if (value.isEncrypted) return crypto.keys.decrypt(encrypted = value.encoded, password = password).orRefuse()
        return SecretBytes.copyOf(value.encoded).use { encoded -> crypto.keys.decodePrivate(encoded).orRefuse() }
    }

    private suspend fun localKeyId(certificate: Certificate): ByteString = crypto.digests.digest(certificate.encoded)

    private suspend fun contentsOf(
        keyBags: List<ByteString>,
        certificateBags: List<ByteString>,
        password: SecretText,
        iterations: Int,
    ): List<ByteString> {
        val contents = mutableListOf<ByteString>()
        if (certificateBags.isNotEmpty()) {
            val plaintext = SecretBytes.copyOf(Pkcs12Writer.safeContents(certificateBags))
            val (algorithm, ciphertext) = plaintext.use { content ->
                PasswordEncryption.encrypt(
                    crypto = crypto,
                    plaintext = content,
                    password = password,
                    iterations = iterations,
                )
            }
            contents += Pkcs12Writer.encrypted(algorithm = algorithm, ciphertext = ciphertext)
        }
        if (keyBags.isNotEmpty()) contents += Pkcs12Writer.plain(Pkcs12Writer.safeContents(keyBags))
        return contents
    }

    private suspend fun protect(authenticated: ByteString, password: SecretText, iterations: Int): ByteString {
        val salt = ByteString(crypto.environment.random.bytes(SALT_BYTES))
        val derived = crypto.derivations.pbkdf2(
            password = password,
            salt = salt,
            iterations = iterations,
            length = MAC_KEY_BYTES,
        )
        val key = derived.use { bytes -> SecretKey.of(bytes) }
        val tag = try {
            crypto.macs.mac(key = key, data = authenticated)
        } finally {
            key.destroy()
        }
        return Pkcs12Writer.pfx(authenticated = authenticated, salt = salt, iterations = iterations, tag = tag)
    }

    private fun <T> Outcome<T, KeyFailure>.orRefuse(): T = when (this) {
        is Outcome.Success -> value
        is Outcome.Failure -> throw KeystoreRefusal(KEY_FAILURES.getValue(failure))
    }

    private companion object {
        val KEY_FAILURES: Map<KeyFailure, KeystoreFailure> = mapOf(
            KeyFailure.Malformed to KeystoreFailure.Malformed,
            KeyFailure.UnsupportedAlgorithm to KeystoreFailure.Unsupported,
            KeyFailure.Refused to KeystoreFailure.Refused,
            KeyFailure.PasswordRequired to KeystoreFailure.WrongPassword,
            KeyFailure.WrongPassword to KeystoreFailure.WrongPassword,
            KeyFailure.UnsupportedEncryption to KeystoreFailure.Unsupported,
        )
    }
}
