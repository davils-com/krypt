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

package com.davils.krypt.x509.crl

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.AlgorithmIdentifiers
import com.davils.krypt.x509.X509Failure
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.internal.CrlCodec
import com.davils.krypt.x509.internal.CrlCodec.readRevocationList
import com.davils.krypt.x509.internal.SignatureChecks
import kotlinx.io.bytestring.ByteString

private const val LABEL: String = "X509 CRL"

/**
 * Reads, writes, verifies and issues certificate revocation lists.
 *
 * The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the limits of reading; a list may be as large as [X509Limits.maximumBytes].
 * @since 1.0.0
 */
public class RevocationLists(public val crypto: Crypto, public val limits: X509Limits = X509Limits.Default) {
    /**
     * Reads a list in DER.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the list, or [X509Failure.Malformed].
     * @since 1.0.0
     */
    public fun decode(encoded: ByteString): Outcome<RevocationList, X509Failure> {
        val list = Der.decodeOrNull(
            encoded,
            DerLimits(maximumBytes = limits.maximumBytes),
        ) { readRevocationList(encoded, limits) }
            ?: return Outcome.Failure(X509Failure.Malformed)
        return Outcome.Success(list)
    }

    /**
     * Reads the first list of a PEM text.
     *
     * @param text the text, possibly from an attacker.
     * @return the list, or [X509Failure.Malformed].
     * @since 1.0.0
     */
    public fun decodePem(text: String): Outcome<RevocationList, X509Failure> {
        val decoded = Pem.decode(text)
        val blocks = decoded.getOrNull().orEmpty()
        val block = blocks.firstOrNull { found -> found.label == LABEL } ?: return Outcome.Failure(
            X509Failure.Malformed,
        )
        return decode(block.bytes)
    }

    /**
     * Writes [list] in PEM.
     *
     * @param list the list.
     * @return the PEM text.
     * @since 1.0.0
     */
    public fun encodePem(list: RevocationList): String = Pem.encode(label = LABEL, bytes = list.encoded)

    /**
     * Verifies the signature of [list] with the public key of its issuer.
     *
     * @param list the list.
     * @param issuerKey the public key of the issuer.
     * @return [Verification.Valid] if the signature is valid by an algorithm the policy permits.
     * @since 1.0.0
     */
    public suspend fun verifySignature(list: RevocationList, issuerKey: PublicKey): Verification =
        SignatureChecks.verify(
            crypto = crypto,
            algorithm = list.signatureAlgorithm,
            key = issuerKey,
            data = list.tbs,
            signature = list.signature,
        )

    /**
     * Issues a list signed by [signer].
     *
     * @param signer the signer of the issuer.
     * @param block describes the list.
     * @return the list.
     * @throws IllegalArgumentException if the issuer, a time or the number is missing.
     * @since 1.0.0
     */
    public suspend fun issue(signer: Signer, block: RevocationListBuilder.() -> Unit): RevocationList {
        val builder = RevocationListBuilder()
        builder.block()
        val tbs = CrlCodec.encodeTbs(builder, signer.algorithm)
        val signature = signer.sign(tbs)
        val encoded = Der.encode {
            sequence {
                raw(tbs)
                raw(AlgorithmIdentifiers.encode(signer.algorithm))
                bitString(BitString(signature))
            }
        }
        return checkNotNull(decode(encoded).getOrNull()) { "The issued list is not valid" }
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RevocationLists($limits)"
}
