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

package com.davils.krypt.primitive.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.core.outcome.map
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

private const val ML_DSA_44_BITS: Int = 44
private const val ML_DSA_65_BITS: Int = 65
private const val ML_DSA_87_BITS: Int = 87
private const val ML_KEM_768_BITS: Int = 768
private const val ML_KEM_1024_BITS: Int = 1_024
private const val ED25519_BITS: Int = 256
private const val ED448_BITS: Int = 456
private const val X25519_BITS: Int = 256
private const val X448_BITS: Int = 448
private const val EC_VERSION: Int = 1
private const val MAXIMUM_VERSION: Int = 1
private const val UNCOMPRESSED: Int = 4
private const val ED25519_PUBLIC: Int = 32
private const val ED448_PUBLIC: Int = 57
private const val X25519_PUBLIC: Int = 32
private const val X448_PUBLIC: Int = 56
private const val ML_DSA_44_PUBLIC: Int = 1_312
private const val ML_DSA_65_PUBLIC: Int = 1_952
private const val ML_DSA_87_PUBLIC: Int = 2_592
private const val ML_KEM_768_PUBLIC: Int = 1_184
private const val ML_KEM_1024_PUBLIC: Int = 1_568

internal object KeyCodec {
    private val FIXED: Map<ObjectIdentifier, KeyInfo> = mapOf(
        Oids.ED25519 to KeyInfo(KeyFamily.Ed25519, curve = null, bits = ED25519_BITS),
        Oids.ED448 to KeyInfo(KeyFamily.Ed448, curve = null, bits = ED448_BITS),
        Oids.X25519 to KeyInfo(KeyFamily.X25519, curve = null, bits = X25519_BITS),
        Oids.X448 to KeyInfo(KeyFamily.X448, curve = null, bits = X448_BITS),
        Oids.ML_DSA_44 to KeyInfo(KeyFamily.MlDsa, curve = null, bits = ML_DSA_44_BITS),
        Oids.ML_DSA_65 to KeyInfo(KeyFamily.MlDsa, curve = null, bits = ML_DSA_65_BITS),
        Oids.ML_DSA_87 to KeyInfo(KeyFamily.MlDsa, curve = null, bits = ML_DSA_87_BITS),
        Oids.ML_KEM_768 to KeyInfo(KeyFamily.MlKem, curve = null, bits = ML_KEM_768_BITS),
        Oids.ML_KEM_1024 to KeyInfo(KeyFamily.MlKem, curve = null, bits = ML_KEM_1024_BITS),
    )

    private val PUBLIC_SIZES: Map<Pair<KeyFamily, Int>, Int> = mapOf(
        (KeyFamily.Ed25519 to ED25519_BITS) to ED25519_PUBLIC,
        (KeyFamily.Ed448 to ED448_BITS) to ED448_PUBLIC,
        (KeyFamily.X25519 to X25519_BITS) to X25519_PUBLIC,
        (KeyFamily.X448 to X448_BITS) to X448_PUBLIC,
        (KeyFamily.MlDsa to ML_DSA_44_BITS) to ML_DSA_44_PUBLIC,
        (KeyFamily.MlDsa to ML_DSA_65_BITS) to ML_DSA_65_PUBLIC,
        (KeyFamily.MlDsa to ML_DSA_87_BITS) to ML_DSA_87_PUBLIC,
        (KeyFamily.MlKem to ML_KEM_768_BITS) to ML_KEM_768_PUBLIC,
        (KeyFamily.MlKem to ML_KEM_1024_BITS) to ML_KEM_1024_PUBLIC,
    )

    private val CURVES: Map<ObjectIdentifier, EllipticCurve> =
        EllipticCurve.entries.associateBy { curve -> ObjectIdentifier.of(curve.objectIdentifier) }

    fun curveOf(oid: ObjectIdentifier): EllipticCurve? = CURVES[oid]

    fun publicKeyOf(spki: ByteString): Outcome<PublicKey, KeyFailure> = PublicKey.decode(spki)

    fun privateKeyOf(pkcs8: SecretBytes): Outcome<PrivateKey, KeyFailure> = PrivateKey.decode(pkcs8)

    fun publicPartsOf(spki: ByteString): Outcome<PublicKeyParts, KeyFailure> {
        val parts = Der.decodeOrNull(spki) {
            readSequence {
                val algorithm = readAlgorithm()
                algorithm to readBitString()
            }
        } ?: return Outcome.Failure(KeyFailure.Malformed)
        return publicInfoOf(algorithm = parts.first, publicKey = parts.second).map { found ->
            PublicKeyParts(info = found, raw = parts.second.bytes)
        }
    }

    fun privatePartsOf(pkcs8: SecretBytes): Outcome<PrivateKeyParts, KeyFailure> {
        val parts = pkcs8.reveal { bytes -> Der.decodeOrNull(ByteString(bytes)) { readPrivateKeyInfo() } }
            ?: return Outcome.Failure(KeyFailure.Malformed)
        return privatePartsOf(parts)
    }

    private fun privatePartsOf(parts: PrivateParts): Outcome<PrivateKeyParts, KeyFailure> {
        val isRsa = parts.algorithm.oid == Oids.RSA_ENCRYPTION
        val rsa = parts.privateKey.takeIf { isRsa }?.let { key -> RsaParameters.privateOf(key) }
        val isRsaMalformed = isRsa && (rsa == null || !hasNullParameters(parts.algorithm))
        val claims = publicClaimsOf(parts = parts, rsaPublic = rsa?.second)
        val spki = claims.firstOrNull()?.let { bits -> spkiOf(algorithm = algorithmOf(parts), publicBits = bits) }
        val publicKey = spki?.let { encoded -> publicKeyOf(encoded) }
        val isPublicMalformed = claims.distinct().size > 1 || publicKey is Outcome.Failure
        if (isRsaMalformed || isPublicMalformed) return Outcome.Failure(KeyFailure.Malformed)
        val info = infoOf(algorithm = parts.algorithm, modulus = rsa?.first)
        return outcomeOf(info) { found -> PrivateKeyParts(info = found, publicKey = publicKey?.getOrNull()) }
    }

    private fun publicInfoOf(algorithm: AlgorithmParts, publicKey: BitString): Outcome<KeyInfo, KeyFailure> {
        val isRsa = algorithm.oid == Oids.RSA_ENCRYPTION
        val modulus = RsaParameters.modulusOf(publicKey.bytes).takeIf { isRsa && hasNullParameters(algorithm) }
        val info = infoOf(algorithm = algorithm, modulus = modulus)
        val isRsaMalformed = isRsa && modulus == null
        val isSized = info == null || hasValidSize(info = info, publicKey = publicKey)
        if (isRsaMalformed || !isSized) return Outcome.Failure(KeyFailure.Malformed)
        return outcomeOf(info) { found -> found }
    }

    private fun hasNullParameters(algorithm: AlgorithmParts): Boolean {
        val parameters = algorithm.parameters
        return parameters?.tag == Tag.Null && parameters.content.size == 0
    }

    private fun hasValidSize(info: KeyInfo, publicKey: BitString): Boolean {
        val size = publicKey.bytes.size
        val fixed = PUBLIC_SIZES[info.family to info.bits]
        val curve = info.curve
        val isPoint = curve != null && size == 1 + 2 * curve.fieldBytes && publicKey.bytes[0].toInt() == UNCOMPRESSED
        val isFixed = fixed != null && size == fixed
        val isVariable = info.family == KeyFamily.Rsa
        return publicKey.unusedBits == 0 && (isPoint || isFixed || isVariable)
    }

    fun spkiOf(algorithm: ByteString, publicBits: BitString): ByteString = Der.encode {
        sequence {
            raw(algorithm)
            bitString(publicBits)
        }
    }

    fun pkcs8Of(algorithm: ByteString, privateKey: ByteString): ByteString = Der.encode {
        sequence {
            integer(0L)
            raw(algorithm)
            octetString(privateKey)
        }
    }

    fun ecAlgorithm(curve: EllipticCurve): ByteString = Der.encode {
        sequence {
            objectIdentifier(Oids.EC_PUBLIC_KEY)
            objectIdentifier(ObjectIdentifier.of(curve.objectIdentifier))
        }
    }

    fun rsaAlgorithm(): ByteString = Der.encode {
        sequence {
            objectIdentifier(Oids.RSA_ENCRYPTION)
            nullValue()
        }
    }

    private fun <T> outcomeOf(info: KeyInfo?, build: (KeyInfo) -> T): Outcome<T, KeyFailure> {
        val found = info ?: return Outcome.Failure(KeyFailure.UnsupportedAlgorithm)
        return Outcome.Success(build(found))
    }

    private fun publicClaimsOf(parts: PrivateParts, rsaPublic: BitString?): List<BitString> {
        val isEc = parts.algorithm.oid == Oids.EC_PUBLIC_KEY
        val ecPublic = parts.privateKey.takeIf { isEc }?.let { key -> ecPublicBitsOf(key) }
        return listOfNotNull(parts.publicBits, rsaPublic, ecPublic)
    }

    private fun algorithmOf(parts: PrivateParts): ByteString =
        parts.algorithm.encoded.takeUnless { parts.algorithm.oid == Oids.RSA_ENCRYPTION } ?: rsaAlgorithm()

    private fun infoOf(algorithm: AlgorithmParts, modulus: DerInteger?): KeyInfo? {
        val fixed = FIXED[algorithm.oid]?.takeIf { algorithm.parameters == null }
        val isEc = algorithm.oid == Oids.EC_PUBLIC_KEY && algorithm.parameters?.tag == Tag.ObjectIdentifier
        val curveOid = algorithm.parameters?.takeIf { isEc }?.let { element ->
            ObjectIdentifier.decodeOrNull(
                element.content,
            )
        }
        val curve = curveOid?.let { oid -> CURVES[oid] }
        val ec = curve?.let { found -> KeyInfo(KeyFamily.Ec, curve = found, bits = found.bits) }
        val rsa = modulus?.let { found -> KeyInfo(KeyFamily.Rsa, curve = null, bits = RsaParameters.bitLength(found)) }
        return fixed ?: ec ?: rsa
    }

    private fun DerReader.readAlgorithm(): AlgorithmParts {
        val element = readElement(Tag.Sequence)
        val body = element.reader()
        val oid = body.readObjectIdentifier()
        val parameters = body.readRemaining()
        if (parameters.size > 1) refuse(DerFailure.TrailingData, "one algorithm parameter")
        return AlgorithmParts(oid = oid, parameters = parameters.firstOrNull(), encoded = element.encoded)
    }

    private fun DerReader.readPrivateKeyInfo(): PrivateParts = readSequence {
        readInt(0..MAXIMUM_VERSION)
        val algorithm = readAlgorithm()
        val privateKey = readOctetString()
        readOptional(Tag.context(number = 0, isConstructed = true))
        val publicBits = readOptional(
            Tag.context(number = 1, isConstructed = false),
        )?.let { element -> bitsOf(element) }
        PrivateParts(algorithm = algorithm, privateKey = privateKey, publicBits = publicBits)
    }

    private fun bitsOf(element: DerElement): BitString? {
        val retagged = Der.encode { element(tag = Tag.BitString, content = element.content) }
        return Der.decodeOrNull(retagged) { readBitString() }
    }

    fun rsaPublicBits(modulus: DerInteger, exponent: DerInteger): BitString =
        RsaParameters.publicBits(modulus = modulus, exponent = exponent)

    private fun ecPublicBitsOf(privateKey: ByteString): BitString? = Der.decodeOrNull(privateKey) {
        readSequence {
            readInt(EC_VERSION..EC_VERSION)
            readOctetString()
            readOptionalExplicit(0) { readObjectIdentifier() }
            readOptionalExplicit(1) { readBitString() }
        }
    }
}
