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

package com.davils.krypt.keystore.material

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.asn1.pem.PemBlock
import com.davils.krypt.keystore.Identities
import com.davils.krypt.keystore.Identity
import com.davils.krypt.keystore.IdentityFailure
import com.davils.krypt.keystore.KeystoreFailure
import com.davils.krypt.keystore.KeystoreLimits
import com.davils.krypt.keystore.internal.MaterialRefusal
import com.davils.krypt.keystore.pkcs12.Pkcs12
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.path.TrustAnchor
import kotlinx.io.bytestring.ByteString

private const val CERTIFICATE: String = "CERTIFICATE"
private const val SEQUENCE: Byte = 0x30
private val KEY_LABELS: Set<String> =
    setOf("PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY")

/**
 * Loads identities, certificates and trust anchors from a [MaterialSource].
 *
 * Every read is bounded by [KeystoreLimits.maximumBytes], every failure is a [MaterialFailure], and nothing is
 * cached: load again to pick up a change. Exceptions of the source are not caught. A loader is safe to share between
 * coroutines.
 *
 * @property crypto the primitives.
 * @property source where the material lies.
 * @property limits the limits of reading.
 * @constructor Loads from [source] with [crypto] within [limits].
 * @since 1.0.0
 */
public class MaterialLoader(
    public val crypto: Crypto,
    public val source: MaterialSource,
    public val limits: KeystoreLimits = KeystoreLimits.Default,
) {
    private val certificateCodec: Certificates = Certificates(crypto)

    /**
     * Loads the identity [spec] describes and proves that its key and its certificate belong together.
     *
     * The chain is ordered from the certificate of the key by issuer, but not validated.
     *
     * @param spec where the identity lies.
     * @return the identity, or why it could not be loaded.
     * @since 1.0.0
     */
    public suspend fun identity(spec: IdentitySpec): Outcome<Identity, MaterialFailure> = attempt {
        when (spec) {
            is IdentitySpec.KeyStore -> fromKeyStore(spec)
            is IdentitySpec.PemBundle -> fromPem(spec)
        }
    }

    /**
     * Loads certificates: the CERTIFICATE blocks of PEM text or a single certificate in DER.
     *
     * @param ref where the certificates lie.
     * @return the certificates in their order, or why they could not be loaded.
     * @since 1.0.0
     */
    public suspend fun certificates(ref: MaterialRef): Outcome<List<Certificate>, MaterialFailure> =
        attempt { certificatesOf(read(ref)) }

    /**
     * Loads trust anchors from the certificates under [ref].
     *
     * @param ref where the certificates lie.
     * @return the anchors, or why they could not be loaded; a certificate whose key the policy forbids is
     *   [MaterialFailure.Unsupported].
     * @since 1.0.0
     */
    public suspend fun anchors(ref: MaterialRef): Outcome<List<TrustAnchor>, MaterialFailure> = attempt {
        val certificates = certificatesOf(read(ref))
        val isReadable = certificates.all { certificate -> certificate.publicKey != null }
        MaterialRefusal.ensure(isReadable, MaterialFailure.Unsupported)
        certificates.map { certificate -> TrustAnchor.of(certificate) }
    }

    /**
     * Shows the source and the limits.
     *
     * @return the loader as text.
     * @since 1.0.0
     */
    override fun toString(): String = "MaterialLoader($source, $limits)"

    private suspend fun fromKeyStore(spec: IdentitySpec.KeyStore): Identity {
        val decoded = Pkcs12(crypto, limits).decode(read(spec.ref), spec.password)
        val store = when (decoded) {
            is Outcome.Success -> decoded.value
            is Outcome.Failure -> throw MaterialRefusal(STORE_FAILURES.getValue(decoded.failure))
        }
        val alias = spec.alias
        if (alias != null) return MaterialRefusal.present(store.key(alias), MaterialFailure.NoKey).identity
        MaterialRefusal.ensure(store.keys.isNotEmpty(), MaterialFailure.NoKey)
        MaterialRefusal.ensure(store.keys.size == 1, MaterialFailure.AmbiguousKey)
        return store.keys.single().identity
    }

    private suspend fun fromPem(spec: IdentitySpec.PemBundle): Identity {
        val certificateBytes = read(spec.certificates)
        val keyBytes = certificateBytes.takeIf { spec.key == spec.certificates } ?: read(spec.key)
        val certificates = certificatesOf(certificateBytes)
        val blocks = blocksOf(keyBytes).filter { block -> block.label in KEY_LABELS }
        MaterialRefusal.ensure(blocks.isNotEmpty(), MaterialFailure.NoKey)
        MaterialRefusal.ensure(blocks.size == 1, MaterialFailure.AmbiguousKey)
        val key = keyOf(blocks.single(), spec)
        return when (val identity = Identities(crypto).of(privateKey = key, certificates = certificates)) {
            is Outcome.Success -> identity.value
            is Outcome.Failure -> throw MaterialRefusal(IDENTITY_FAILURES.getValue(identity.failure))
        }
    }

    private suspend fun keyOf(block: PemBlock, spec: IdentitySpec.PemBundle): PrivateKey {
        val decoded = crypto.keys.decodePrivatePem(text = Pem.encode(listOf(block)), password = spec.password)
        return when (decoded) {
            is Outcome.Success -> decoded.value
            is Outcome.Failure -> throw MaterialRefusal(KEY_FAILURES.getValue(decoded.failure))
        }
    }

    private fun certificatesOf(bytes: ByteString): List<Certificate> {
        val isDer = bytes.size > 0 && bytes[0] == SEQUENCE
        if (isDer) return listOf(certificateCodec.decode(bytes).orMalformed())
        val blocks = blocksOf(bytes).filter { block -> block.label == CERTIFICATE }
        MaterialRefusal.ensure(blocks.isNotEmpty(), MaterialFailure.NoCertificate)
        return blocks.map { block -> certificateCodec.decode(block.bytes).orMalformed() }
    }

    private fun blocksOf(bytes: ByteString): List<PemBlock> {
        val isAscii = (0 until bytes.size).all { index -> bytes[index] >= 0 }
        MaterialRefusal.ensure(isAscii, MaterialFailure.Malformed)
        return Pem.decode(bytes.toByteArray().decodeToString()).orMalformed()
    }

    private suspend fun read(ref: MaterialRef): ByteString = when (val read = source.read(ref, limits.maximumBytes)) {
        is MaterialRead.Found -> sized(read.bytes)
        MaterialRead.Missing -> throw MaterialRefusal(MaterialFailure.Missing)
        MaterialRead.Unavailable -> throw MaterialRefusal(MaterialFailure.Unavailable)
    }

    private fun sized(bytes: ByteString): ByteString {
        MaterialRefusal.ensure(bytes.size <= limits.maximumBytes, MaterialFailure.TooLarge)
        return bytes
    }

    private fun <T> Outcome<T, *>.orMalformed(): T = when (this) {
        is Outcome.Success -> value
        is Outcome.Failure -> throw MaterialRefusal(MaterialFailure.Malformed)
    }

    private suspend fun <T> attempt(block: suspend () -> T): Outcome<T, MaterialFailure> = try {
        Outcome.Success(block())
    } catch (refusal: MaterialRefusal) {
        Outcome.Failure(refusal.failure)
    }

    private companion object {
        val STORE_FAILURES: Map<KeystoreFailure, MaterialFailure> = mapOf(
            KeystoreFailure.Malformed to MaterialFailure.Malformed,
            KeystoreFailure.WrongPassword to MaterialFailure.WrongPassword,
            KeystoreFailure.Unsupported to MaterialFailure.Unsupported,
            KeystoreFailure.Refused to MaterialFailure.Refused,
        )

        val KEY_FAILURES: Map<KeyFailure, MaterialFailure> = mapOf(
            KeyFailure.Malformed to MaterialFailure.Malformed,
            KeyFailure.UnsupportedAlgorithm to MaterialFailure.Unsupported,
            KeyFailure.Refused to MaterialFailure.Refused,
            KeyFailure.PasswordRequired to MaterialFailure.WrongPassword,
            KeyFailure.WrongPassword to MaterialFailure.WrongPassword,
            KeyFailure.UnsupportedEncryption to MaterialFailure.Unsupported,
        )

        val IDENTITY_FAILURES: Map<IdentityFailure, MaterialFailure> = mapOf(
            IdentityFailure.NoCertificate to MaterialFailure.NoCertificate,
            IdentityFailure.KeyMismatch to MaterialFailure.KeyMismatch,
        )
    }
}
