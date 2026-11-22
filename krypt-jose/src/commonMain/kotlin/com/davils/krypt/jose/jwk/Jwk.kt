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
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.internal.JwkWriter
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

private const val NONE: String = "none"

/**
 * A JSON Web Key of RFC 7517: an EC, OKP, RSA or symmetric key with its metadata.
 *
 * The public parameters (`x`, `y`, `n`, `e`) are plain values; the private parameters (`d`, `p`, `q`, `dp`, `dq`,
 * `qi`) and the symmetric key `k` live in [SecretBytes], never appear in [toString] and are wiped by [destroy]. A JWK
 * is read by [JsonWebKeys.decode] or made from a key of krypt by [JsonWebKeys.of]; [JsonWebKeys] turns it into a key
 * of krypt. Members krypt does not interpret, such as `x5u` or `x5t#S256`, are kept in [extra].
 *
 * A JWK is immutable apart from [destroy] and may be shared between threads; destroying it while another thread uses
 * it makes that use fail.
 *
 * @property type the key type.
 * @property curve the curve of an EC or OKP key, null for RSA and symmetric keys.
 * @property use the `use` member, or null.
 * @param operations the `key_ops` member.
 * @property algorithm the `alg` member, or null.
 * @property keyId the `kid` member, or null.
 * @param certificates the certificates of the `x5c` member.
 * @property parameters the public parameters, decoded.
 * @property secrets the private parameters, decoded.
 * @property extra the members krypt keeps but does not interpret.
 * @since 1.0.0
 */
public class Jwk internal constructor(
    public val type: JwkType,
    public val curve: JwkCurve?,
    public val use: KeyUse?,
    operations: List<KeyOperation>,
    public val algorithm: String?,
    public val keyId: String?,
    certificates: List<Certificate>,
    internal val parameters: List<Pair<String, ByteString>>,
    internal val secrets: List<Pair<String, SecretBytes>>,
    public val extra: JsonValue.Object,
) {
    /**
     * The `key_ops` member, empty if absent.
     *
     * @since 1.0.0
     */
    public val operations: List<KeyOperation> = operations.toList()

    /**
     * The certificates of the `x5c` member, the one of this key first; empty if absent.
     *
     * @since 1.0.0
     */
    public val certificates: List<Certificate> = certificates.toList()

    /**
     * Tells whether the JWK holds a private or a symmetric key.
     *
     * @since 1.0.0
     */
    public val isPrivate: Boolean = secrets.isNotEmpty()

    /**
     * Tells whether [destroy] was called.
     *
     * @since 1.0.0
     */
    public val isDestroyed: Boolean get() = secrets.any { (_, secret) -> secret.isDestroyed }

    private val metadata: List<Any?>
        get() = listOf(type, curve, use, operations, algorithm, keyId, certificates, extra)

    /**
     * Returns the public parameter [name], such as `x`, `y`, `n` or `e`, decoded from Base64url.
     *
     * @param name the parameter name.
     * @return the bytes, or null if the key has no such public parameter.
     * @since 1.0.0
     */
    public fun parameter(name: String): ByteString? = parameters.firstOrNull { (found, _) -> found == name }?.second

    /**
     * Returns the JWK without its private parameters.
     *
     * @return the public JWK, or null for a symmetric key, which has no public part.
     * @since 1.0.0
     */
    public fun toPublic(): Jwk? {
        if (type == JwkType.Oct) return null
        return Jwk(
            type = type,
            curve = curve,
            use = use,
            operations = operations,
            algorithm = algorithm,
            keyId = keyId,
            certificates = certificates,
            parameters = parameters,
            secrets = emptyList(),
            extra = extra,
        )
    }

    /**
     * Writes the JWK as compact JSON, private parameters included.
     *
     * @return the JSON text, which holds the private key of a private JWK in the clear.
     * @throws IllegalStateException if the JWK was destroyed.
     * @since 1.0.0
     */
    public fun encode(): String {
        check(!isDestroyed) { "The JWK was destroyed, so it cannot be written any more" }
        return JwkWriter.objectOf(this).encode()
    }

    internal fun secret(name: String): SecretBytes? = secrets.firstOrNull { (found, _) -> found == name }?.second

    /**
     * Wipes the private parameters. Destroying twice does nothing.
     *
     * @since 1.0.0
     */
    public fun destroy() {
        secrets.forEach { (_, secret) -> secret.destroy() }
    }

    /**
     * Compares every member; private parameters in constant time.
     *
     * @param other the other object.
     * @return true if [other] is the same key with the same metadata.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Jwk &&
        metadata == other.metadata &&
        parameters == other.parameters &&
        secrets == other.secrets

    /**
     * Hashes the public members.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(metadata, parameters).hashCode()

    /**
     * Shows the type, the curve, the id and whether the key is private, never a private parameter.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Jwk(${type.typeName}, crv=${curve?.curveName ?: NONE}, " +
        "kid=${SafeText.text(keyId ?: NONE)}, alg=${SafeText.text(algorithm ?: NONE)}, private=$isPrivate)"
}
