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

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.internal.X509Oids
import kotlinx.io.bytestring.ByteString

private const val PSS_SALT: Int = 2
private const val PSS_MASK: Int = 1
private const val PSS_HASH: Int = 0

/**
 * The algorithm identifiers of signatures in X.509, OCSP and CMS: the object identifier and the parameters of every
 * signature algorithm krypt verifies, with RSASSA-PSS restricted to the parameters RFC 4055 recommends.
 *
 * SHA-1 and MD5 signatures are not mapped and read as unsupported.
 *
 * @since 1.0.0
 */
@DavilsInternal
public object AlgorithmIdentifiers {
    private val SIMPLE: Map<ObjectIdentifier, SignatureAlgorithm> = mapOf(
        X509Oids.ECDSA_SHA256 to SignatureAlgorithm.EcdsaSha256,
        X509Oids.ECDSA_SHA384 to SignatureAlgorithm.EcdsaSha384,
        X509Oids.ECDSA_SHA512 to SignatureAlgorithm.EcdsaSha512,
        X509Oids.ED25519 to SignatureAlgorithm.Ed25519,
        X509Oids.ED448 to SignatureAlgorithm.Ed448,
        X509Oids.ML_DSA_44 to SignatureAlgorithm.MlDsa44,
        X509Oids.ML_DSA_65 to SignatureAlgorithm.MlDsa65,
        X509Oids.ML_DSA_87 to SignatureAlgorithm.MlDsa87,
    )

    private val PKCS1: Map<ObjectIdentifier, SignatureAlgorithm> = mapOf(
        X509Oids.SHA256_WITH_RSA to SignatureAlgorithm.RsaPkcs1Sha256,
        X509Oids.SHA384_WITH_RSA to SignatureAlgorithm.RsaPkcs1Sha384,
        X509Oids.SHA512_WITH_RSA to SignatureAlgorithm.RsaPkcs1Sha512,
    )

    private val PSS: Map<DigestAlgorithm, SignatureAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to SignatureAlgorithm.RsaPssSha256,
        DigestAlgorithm.Sha384 to SignatureAlgorithm.RsaPssSha384,
        DigestAlgorithm.Sha512 to SignatureAlgorithm.RsaPssSha512,
    )

    private val DIGESTS: Map<ObjectIdentifier, DigestAlgorithm> = mapOf(
        X509Oids.SHA256 to DigestAlgorithm.Sha256,
        X509Oids.SHA384 to DigestAlgorithm.Sha384,
        X509Oids.SHA512 to DigestAlgorithm.Sha512,
    )

    private val SIMPLE_OIDS: Map<SignatureAlgorithm, ObjectIdentifier> = inverted(SIMPLE)
    private val PKCS1_OIDS: Map<SignatureAlgorithm, ObjectIdentifier> = inverted(PKCS1)
    private val PSS_DIGESTS: Map<SignatureAlgorithm, DigestAlgorithm> = inverted(PSS)
    private val DIGEST_OIDS: Map<DigestAlgorithm, ObjectIdentifier> = inverted(DIGESTS)

    /**
     * Writes the algorithm identifier of [algorithm].
     *
     * @receiver the writer.
     * @param algorithm the signature algorithm.
     * @throws IllegalArgumentException if [algorithm] has no identifier in X.509, such as a legacy algorithm.
     * @since 1.0.0
     */
    public fun DerWriter.writeSignatureAlgorithm(algorithm: SignatureAlgorithm) {
        val digest = PSS_DIGESTS[algorithm]
        val oid = SIMPLE_OIDS[algorithm] ?: PKCS1_OIDS[algorithm] ?: X509Oids.RSASSA_PSS.takeIf { digest != null }
        requireNotNull(oid) { "$algorithm has no identifier in X.509" }
        sequence {
            objectIdentifier(oid)
            if (algorithm in PKCS1_OIDS) nullValue()
            digest?.let { found -> writePssParameters(found) }
        }
    }

    /**
     * Encodes the algorithm identifier of [algorithm].
     *
     * @param algorithm the signature algorithm.
     * @return the DER encoding.
     * @throws IllegalArgumentException if [algorithm] has no identifier in X.509.
     * @since 1.0.0
     */
    public fun encode(algorithm: SignatureAlgorithm): ByteString = Der.encode { writeSignatureAlgorithm(algorithm) }

    /**
     * Reads an algorithm identifier of a signature.
     *
     * @receiver the reader.
     * @return the algorithm, or null if krypt does not know it or its parameters.
     * @throws com.davils.krypt.asn1.DerException if the identifier is malformed.
     * @since 1.0.0
     */
    public fun DerReader.readSignatureAlgorithm(): SignatureAlgorithm? = readSequence {
        val oid = readObjectIdentifier()
        val simple = SIMPLE[oid]?.takeIf { isExhausted }
        val pkcs1 = PKCS1[oid]?.takeIf { _ -> skipNull() }
        val pss = oid.takeIf { found -> found == X509Oids.RSASSA_PSS }?.let { readPss() }
        while (!isExhausted) readElement()
        simple ?: pkcs1 ?: pss
    }

    private fun DerReader.skipNull(): Boolean {
        if (isNext(Tag.Null)) readNull()
        return isExhausted
    }

    private fun <K, V> inverted(map: Map<K, V>): Map<V, K> = map.entries.associate { (key, value) -> value to key }

    private fun DerWriter.writePssParameters(digest: DigestAlgorithm) {
        val digestOid = DIGEST_OIDS.getValue(digest)
        sequence {
            explicit(PSS_HASH) { sequence { objectIdentifier(digestOid) } }
            explicit(PSS_MASK) {
                sequence {
                    objectIdentifier(X509Oids.MGF1)
                    sequence { objectIdentifier(digestOid) }
                }
            }
            explicit(PSS_SALT) { integer(digest.outputBytes.toLong()) }
        }
    }

    private fun DerReader.readPss(): SignatureAlgorithm? = readSequence {
        val hash = readOptionalExplicit(PSS_HASH) { readDigest() }
        val mask = readOptionalExplicit(PSS_MASK) {
            readSequence {
                val isMgf1 = readObjectIdentifier() == X509Oids.MGF1
                readDigest().takeIf { isMgf1 }
            }
        }
        val salt = readOptionalExplicit(PSS_SALT) { readInt(0..Int.MAX_VALUE) }
        while (!isExhausted) readElement()
        val isConsistent = hash != null && hash == mask && salt == hash.outputBytes
        hash?.takeIf { isConsistent }?.let { digest -> PSS[digest] }
    }

    private fun DerReader.readDigest(): DigestAlgorithm? = readSequence {
        val digest = DIGESTS[readObjectIdentifier()]
        digest.takeIf { skipNull() }
    }
}
