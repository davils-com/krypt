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

package com.davils.krypt.jose.jwk

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.core.outcome.map
import com.davils.kore.core.outcome.mapFailure
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.Base64Url
import com.davils.krypt.jose.internal.HeaderReader
import com.davils.krypt.jose.internal.JwkNames
import com.davils.krypt.jose.internal.JwkReader
import com.davils.krypt.jose.internal.JwkWriter
import com.davils.krypt.jose.internal.KeyDer
import com.davils.krypt.jose.internal.decoding
import com.davils.krypt.jose.internal.invariant
import com.davils.krypt.jose.internal.refuseUnless
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString

/**
 * Reads, writes and converts JSON Web Keys of RFC 7517 and RFC 8037, and computes their thumbprints of RFC 7638 and
 * thumbprint URIs of RFC 9278.
 *
 * Decoding is strict: the JSON follows I-JSON within [limits], every parameter is canonical Base64url, the
 * coordinates of an EC key and the keys of an OKP key have exactly the size of their curve, the integers of an RSA
 * key have no leading zero, a private RSA key carries every CRT parameter, a parameter of another key type is refused,
 * `use` and `key_ops` agree, and the first certificate of `x5c` holds the key of the JWK. A multi-prime RSA key
 * (`oth`) is refused. Converting a JWK into a key of krypt asks the crypto policy, and a private EC or OKP key must
 * belong to its public parameters.
 *
 * The object holds no state of its own and is safe to share between threads.
 *
 * @property crypto the crypto of the conversions and digests.
 * @property limits the limits of decoding.
 * @since 1.0.0
 */
public class JsonWebKeys(public val crypto: Crypto, public val limits: JoseLimits = JoseLimits.Default) {
    private val reader = JwkReader(Certificates(crypto), limits)
    private val headers = HeaderReader(limits)

    /**
     * Reads a JWK.
     *
     * @param text the JSON text, possibly from an attacker.
     * @return the key, or why it was refused.
     * @since 1.0.0
     */
    public fun decode(text: String): Outcome<Jwk, JoseFailure> = objectOf(text).flatMap { json -> read(json) }

    /**
     * Reads a JWK from a parsed JSON object, for the formats of other krypt modules that embed JWKs with members of
     * their own, such as the SPIFFE bundles of krypt-spiffe. The rules of [decode] apply.
     *
     * @param json the object, possibly from an attacker.
     * @return the key, or why it was refused.
     * @since 1.0.0
     */
    @DavilsInternal
    public fun read(json: JsonValue.Object): Outcome<Jwk, JoseFailure> = decoding { reader.read(json) }

    /**
     * Parses a JSON object by the strict and bounded rules of krypt-jose: I-JSON within [limits], no duplicate member.
     *
     * @param text the JSON text, possibly from an attacker.
     * @return the object, or why it was refused.
     * @since 1.0.0
     */
    @DavilsInternal
    public fun parse(text: String): Outcome<JsonValue.Object, JoseFailure> = objectOf(text)

    /**
     * Writes [jwk] as a JSON object, for the formats of other krypt modules that add members of their own.
     *
     * @param jwk the key.
     * @return the members of the JWK.
     * @throws IllegalStateException if [jwk] was destroyed.
     * @since 1.0.0
     */
    @DavilsInternal
    public fun members(jwk: Jwk): JsonValue.Object {
        check(!jwk.isDestroyed) { "The JWK was destroyed, so it cannot be written any more" }
        return JwkWriter.objectOf(jwk)
    }

    /**
     * Reads a JWK set. A key that krypt cannot read, such as one of an unknown type, is left out, as RFC 7517
     * demands; a set of more than [JoseLimits.maximumKeys] keys is refused.
     *
     * @param text the JSON text, possibly from an attacker.
     * @return the set, or why it was refused.
     * @since 1.0.0
     */
    public fun decodeSet(text: String): Outcome<JwkSet, JoseFailure> = objectOf(text).flatMap { json ->
        decoding {
            val value = json[JwkNames.KEYS]
            require(value is JsonValue.Array)
            val items = value.items
            refuseUnless(items.size <= limits.maximumKeys, JoseFailure.LimitExceeded)
            val keys = items.mapNotNull { item ->
                require(item is JsonValue.Object)
                decoding { reader.read(item) }.getOrNull()
            }
            JwkSet(keys)
        }
    }

    /**
     * Writes [key] as a public JWK.
     *
     * @param key the public key: EC, Ed25519, Ed448, X25519, X448 or RSA.
     * @param keyId the `kid` member, or null.
     * @param use the `use` member, or null.
     * @param algorithm the `alg` member, or null.
     * @return the JWK.
     * @throws IllegalArgumentException if JOSE has no key type for [key], such as ML-DSA.
     * @since 1.0.0
     */
    public fun of(key: PublicKey, keyId: String? = null, use: KeyUse? = null, algorithm: String? = null): Jwk {
        val (type, curve) = typeOf(key.family, key)
        val size = curve?.publicBytes ?: 0
        return Jwk(
            type = type,
            curve = curve,
            use = use,
            operations = emptyList(),
            algorithm = algorithm,
            keyId = keyId,
            certificates = emptyList(),
            parameters = KeyDer.publicParameters(type = type, size = size, key = key),
            secrets = emptyList(),
            extra = JsonValue.Object.Empty,
        )
    }

    /**
     * Writes [key] as a private JWK with its public parameters.
     *
     * @param key an extractable private key whose public key is known.
     * @param keyId the `kid` member, or null.
     * @param use the `use` member, or null.
     * @param algorithm the `alg` member, or null.
     * @return the JWK, which the caller should destroy.
     * @throws IllegalArgumentException if JOSE has no key type for [key] or its public key is unknown, as for an
     *   X25519 key read from PKCS #8 without one; pair it first with `crypto.keys.pair`.
     * @throws IllegalStateException if [key] is not extractable or was destroyed.
     * @since 1.0.0
     */
    public fun of(key: PrivateKey, keyId: String? = null, use: KeyUse? = null, algorithm: String? = null): Jwk {
        val publicKey = requireNotNull(key.publicKey) { "The public key of the private key is unknown" }
        val publicJwk = of(key = publicKey, keyId = keyId, use = use, algorithm = algorithm)
        val secrets = crypto.keys.encodePrivate(key).use { pkcs8 ->
            val size = publicJwk.curve?.privateBytes ?: 0
            KeyDer.privateParameters(type = publicJwk.type, size = size, pkcs8 = pkcs8)
        }
        return Jwk(
            type = publicJwk.type,
            curve = publicJwk.curve,
            use = use,
            operations = emptyList(),
            algorithm = algorithm,
            keyId = keyId,
            certificates = emptyList(),
            parameters = publicJwk.parameters,
            secrets = secrets,
            extra = JsonValue.Object.Empty,
        )
    }

    /**
     * Writes [key] as a symmetric JWK.
     *
     * @param key the symmetric key.
     * @param keyId the `kid` member, or null.
     * @param algorithm the `alg` member, or null.
     * @return the JWK, which the caller should destroy.
     * @throws IllegalStateException if [key] was destroyed.
     * @since 1.0.0
     */
    public fun of(key: SecretKey, keyId: String? = null, algorithm: String? = null): Jwk = Jwk(
        type = JwkType.Oct,
        curve = null,
        use = null,
        operations = emptyList(),
        algorithm = algorithm,
        keyId = keyId,
        certificates = emptyList(),
        parameters = emptyList(),
        secrets = listOf(JwkNames.K to key.export()),
        extra = JsonValue.Object.Empty,
    )

    /**
     * Returns the public key of [jwk].
     *
     * @param jwk an EC, OKP or RSA key, public or private.
     * @return the key, or [JoseFailure.InvalidKey] for a symmetric key or one the policy refuses.
     * @since 1.0.0
     */
    public fun publicKey(jwk: Jwk): Outcome<PublicKey, JoseFailure> {
        if (jwk.type == JwkType.Oct) return Outcome.Failure(JoseFailure.InvalidKey)
        return crypto.keys.decodePublic(KeyDer.spki(jwk)).mapFailure { _ -> JoseFailure.InvalidKey }
    }

    /**
     * Returns the private key of [jwk]. A private EC or OKP key is proven to belong to its public parameters by a
     * signature or a key agreement with the key.
     *
     * @param jwk a private EC, OKP or RSA key.
     * @return the key, which the caller should destroy, or [JoseFailure.InvalidKey] for a public or symmetric key,
     *   one the policy refuses or one whose parts do not belong together.
     * @since 1.0.0
     */
    public suspend fun privateKey(jwk: Jwk): Outcome<PrivateKey, JoseFailure> {
        val isAsymmetricPrivate = jwk.isPrivate && jwk.type != JwkType.Oct
        if (!isAsymmetricPrivate) return Outcome.Failure(JoseFailure.InvalidKey)
        val decoded = KeyDer.pkcs8(jwk).use { pkcs8 -> crypto.keys.decodePrivate(pkcs8) }
        return decoded.mapFailure { _ -> JoseFailure.InvalidKey }.flatMap { key -> paired(jwk, key) }
    }

    /**
     * Returns the symmetric key of [jwk].
     *
     * @param jwk a symmetric key of at least 16 bytes.
     * @return the key, which the caller should destroy, or [JoseFailure.InvalidKey] for another key type or a
     *   shorter key.
     * @since 1.0.0
     */
    public fun secretKey(jwk: Jwk): Outcome<SecretKey, JoseFailure> {
        val material = jwk.secret(JwkNames.K)
        val isUsable = material != null && material.size >= SecretKey.MINIMUM_BYTES
        if (!isUsable) return Outcome.Failure(JoseFailure.InvalidKey)
        return Outcome.Success(SecretKey.of(material))
    }

    /**
     * Returns [jwk] as a key of JOSE with its key id: a symmetric, a private or a public key.
     *
     * @param jwk the JWK.
     * @return the key, or why it is unusable.
     * @since 1.0.0
     */
    public suspend fun key(jwk: Jwk): Outcome<JoseKey, JoseFailure> = when (jwk.type) {
        JwkType.Oct -> secretKey(jwk).map { key -> JoseKey.Secret(key = key, keyId = jwk.keyId) }
        JwkType.Ec -> asymmetricKey(jwk)
        JwkType.Okp -> asymmetricKey(jwk)
        JwkType.Rsa -> asymmetricKey(jwk)
    }

    /**
     * Computes the thumbprint of RFC 7638: the digest of the required members of [jwk] in lexicographic order.
     *
     * @param jwk the JWK; the thumbprint of a private key is the one of its public key.
     * @param algorithm the digest; SHA-256 by default.
     * @return the thumbprint.
     * @throws IllegalStateException if a symmetric [jwk] was destroyed.
     * @since 1.0.0
     */
    public suspend fun thumbprint(jwk: Jwk, algorithm: DigestAlgorithm = DigestAlgorithm.Sha256): ByteString =
        crypto.digests.digest(data = ByteString(JwkWriter.thumbprintInput(jwk)), algorithm = algorithm)

    /**
     * Computes the thumbprint URI of RFC 9278, such as `urn:ietf:params:oauth:jwk-thumbprint:sha-256:...`.
     *
     * @param jwk the JWK.
     * @param algorithm SHA-256, SHA-384 or SHA-512; SHA-256 by default.
     * @return the URI.
     * @throws IllegalArgumentException if [algorithm] has no name in the registry of hash algorithms.
     * @since 1.0.0
     */
    public suspend fun thumbprintUri(jwk: Jwk, algorithm: DigestAlgorithm = DigestAlgorithm.Sha256): String {
        val name = requireNotNull(HASH_NAMES[algorithm]) { "${algorithm.algorithmName} has no thumbprint URI" }
        return "$THUMBPRINT_URN$name:${Base64Url.encode(thumbprint(jwk, algorithm))}"
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "JsonWebKeys($limits)"

    private fun objectOf(text: String): Outcome<JsonValue.Object, JoseFailure> = decoding { headers.objectOf(text) }

    private suspend fun asymmetricKey(jwk: Jwk): Outcome<JoseKey, JoseFailure> = when (jwk.isPrivate) {
        true -> privateKey(jwk).map { key -> JoseKey.Private(key = key, keyId = jwk.keyId) }
        false -> publicKey(jwk).map { key -> JoseKey.Public(key = key, keyId = jwk.keyId) }
    }

    private suspend fun paired(jwk: Jwk, key: PrivateKey): Outcome<PrivateKey, JoseFailure> {
        if (jwk.type == JwkType.Rsa) return Outcome.Success(key)
        val pair = pairOrNull(key, invariant(publicKey(jwk).getOrNull()))
        return pair?.let { found -> Outcome.Success(found) } ?: Outcome.Failure(JoseFailure.InvalidKey)
    }

    private suspend fun pairOrNull(key: PrivateKey, publicKey: PublicKey): PrivateKey? = try {
        crypto.keys.pair(privateKey = key, publicKey = publicKey)?.privateKey
    } catch (ignored: CryptoException) {
        null
    } finally {
        key.destroy()
    }

    private fun typeOf(family: KeyFamily, key: PublicKey): Pair<JwkType, JwkCurve?> {
        val type = requireNotNull(TYPES[family]) { "JOSE has no key type for a $family key" }
        return type to JwkCurve.of(family, key.curve)
    }

    private companion object {
        const val THUMBPRINT_URN: String = "urn:ietf:params:oauth:jwk-thumbprint:"

        val TYPES: Map<KeyFamily, JwkType> = mapOf(
            KeyFamily.Ec to JwkType.Ec,
            KeyFamily.Ed25519 to JwkType.Okp,
            KeyFamily.Ed448 to JwkType.Okp,
            KeyFamily.X25519 to JwkType.Okp,
            KeyFamily.X448 to JwkType.Okp,
            KeyFamily.Rsa to JwkType.Rsa,
        )

        val HASH_NAMES: Map<DigestAlgorithm, String> = mapOf(
            DigestAlgorithm.Sha256 to "sha-256",
            DigestAlgorithm.Sha384 to "sha-384",
            DigestAlgorithm.Sha512 to "sha-512",
        )
    }
}
