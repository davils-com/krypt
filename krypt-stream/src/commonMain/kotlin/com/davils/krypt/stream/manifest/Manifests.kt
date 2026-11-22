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

package com.davils.krypt.stream.manifest

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.io.ByteSource
import com.davils.krypt.keyset.KeysetSigner
import com.davils.krypt.keyset.KeysetVerifier
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.internal.Chunks
import com.davils.krypt.stream.internal.HeaderCodec
import com.davils.krypt.stream.internal.ManifestCodec
import com.davils.krypt.stream.internal.MerkleTree
import com.davils.krypt.stream.internal.Octets
import kotlinx.io.bytestring.ByteString

private const val DEFAULT_SEGMENT_SIZE: Int = 65_536
private const val SIGNATURE_LABEL: String = "KRYPT/1 manifest "
private const val COUNTERSIGNATURE_LABEL: String = "KRYPT/1 countersignature "

/**
 * Builds, signs, countersigns and verifies [Manifest]s, so that large data or a whole container is signed once and
 * checked as it streams past, without holding it in memory.
 *
 * A signature covers a label, the version and every property of the manifest; a countersignature also covers the
 * signature it countersigns. Signers and verifiers are key sets, so keys rotate without breaking old signatures.
 *
 * Time-stamp tokens are carried as opaque bytes: krypt neither verifies them nor checks what they cover, and neither
 * [verify] nor [decode] looks at them. A caller that relies on the time of a signature verifies the token itself, for
 * example a time-stamp token of RFC 3161 with its time-stamping authority, and checks that its message imprint is the
 * digest of the signature it belongs to.
 *
 * The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives.
 * @property limits the limits of manifests.
 * @since 1.0.0
 */
public class Manifests(public val crypto: Crypto, public val limits: StreamLimits = StreamLimits.Default) {
    /**
     * Builds the manifest of the data [source] holds.
     *
     * @param source the data.
     * @param segmentSize the size of a segment, 4 KiB to 8 MiB; 64 KiB by default.
     * @param digest the digest of the tree; SHA-256 by default.
     * @return the manifest.
     * @throws IllegalArgumentException if [segmentSize] is out of range or [digest] is not supported.
     * @since 1.0.0
     */
    public suspend fun of(
        source: ByteSource,
        segmentSize: Int = DEFAULT_SEGMENT_SIZE,
        digest: DigestAlgorithm = DigestAlgorithm.Sha256,
    ): Manifest {
        require(segmentSize in HeaderCodec.MINIMUM_SEGMENT..HeaderCodec.MAXIMUM_SEGMENT) {
            "A segment has ${HeaderCodec.MINIMUM_SEGMENT} to ${HeaderCodec.MAXIMUM_SEGMENT} bytes"
        }
        require(digest in Manifest.DIGESTS) { "A manifest uses SHA-256, SHA-384 or SHA-512" }
        val tree = MerkleTree(crypto, digest)
        val chunks = Chunks(source, segmentSize)
        var length = 0L
        var chunk = chunks.nextOrNull()
        while (chunk != null) {
            val segment = chunk.first
            if (segment.size > 0) tree.add(segment)
            length += segment.size
            chunk = chunks.nextOrNull()
        }
        return Manifest(
            kind = ManifestKind.Data,
            digest = digest,
            segmentSize = segmentSize,
            length = length,
            segments = tree.leaves,
            root = tree.root(),
        )
    }

    /**
     * Tells whether the data [source] holds is the data [manifest] describes.
     *
     * @param manifest a manifest of [ManifestKind.Data].
     * @param source the data, possibly changed.
     * @return true if the data matches.
     * @throws IllegalArgumentException if [manifest] describes a container; use the seal of the container instead.
     * @since 1.0.0
     */
    public suspend fun matches(manifest: Manifest, source: ByteSource): Boolean {
        require(manifest.kind == ManifestKind.Data) { "A container is matched by its seal" }
        val actual = of(source = source, segmentSize = manifest.segmentSize, digest = manifest.digest)
        return actual == manifest
    }

    /**
     * Signs [manifest] with every signer.
     *
     * @param manifest the manifest.
     * @param signers the signers; at least one.
     * @return the signed manifest.
     * @throws IllegalArgumentException if there are no or too many signers.
     * @since 1.0.0
     */
    public suspend fun sign(manifest: Manifest, signers: List<KeysetSigner>): SignedManifest {
        require(
            signers.size in 1..limits.maximumSignatures,
        ) { "A manifest has 1 to ${limits.maximumSignatures} signatures" }
        val message = signedPart(manifest)
        val signatures = signers.map { signer -> ManifestSignature(signer.sign(message)) }
        return SignedManifest(manifest, signatures)
    }

    /**
     * Adds a countersignature of [signer] over the signature [index] of [signed], such as the approval of a second
     * person.
     *
     * @param signed the signed manifest.
     * @param index the signature to countersign.
     * @param signer the countersigner.
     * @return the signed manifest with the countersignature.
     * @throws IllegalArgumentException if [index] is out of range or the manifest is full.
     * @since 1.0.0
     */
    public suspend fun countersign(signed: SignedManifest, index: Int, signer: KeysetSigner): SignedManifest {
        require(index in signed.signatures.indices) { "The manifest has no signature $index" }
        require(
            signed.signatures.size < limits.maximumSignatures,
        ) { "The manifest holds ${limits.maximumSignatures} signatures" }
        val message = counterPart(signed.manifest, signed.signatures[index])
        val countersignature = ManifestSignature(signature = signer.sign(message), countersigns = index)
        return SignedManifest(signed.manifest, signed.signatures + countersignature)
    }

    /**
     * Attaches a time-stamp [token] to the signature [index]. The token is kept as it is and never verified.
     *
     * @param signed the signed manifest.
     * @param index the signature.
     * @param token the opaque token of a time-stamping authority over that signature.
     * @return the signed manifest with the token.
     * @throws IllegalArgumentException if [index] is out of range.
     * @since 1.0.0
     */
    public fun timestamp(signed: SignedManifest, index: Int, token: ByteString): SignedManifest {
        require(index in signed.signatures.indices) { "The manifest has no signature $index" }
        val signatures = signed.signatures.mapIndexed { position, signature ->
            signature.takeUnless { position == index } ?: ManifestSignature(
                signature = signature.signature,
                countersigns = signature.countersigns,
                timestamp = token,
            )
        }
        return SignedManifest(signed.manifest, signatures)
    }

    /**
     * Verifies that [verifier] signed the manifest.
     *
     * @param signed the signed manifest, possibly from an attacker.
     * @param verifier the key set of the expected signer.
     * @return [Verification.Valid] if a signature of the manifest, not a countersignature, verifies.
     * @since 1.0.0
     */
    public suspend fun verify(signed: SignedManifest, verifier: KeysetVerifier): Verification {
        val message = signedPart(signed.manifest)
        val direct = signed.signatures.filter { signature -> signature.countersigns == null }
        val isValid = direct.any { signature ->
            isSignedBy(
                verifier = verifier,
                message = message,
                signature = signature,
            )
        }
        return Verification.of(isValid)
    }

    /**
     * Verifies that every one of [verifiers] signed the manifest, as when several parties must agree.
     *
     * Each verifier needs one signature it verifies, and one signature satisfies every verifier that holds its key:
     * verifiers of key sets that share a key are not distinct parties, so give every party a key set of its own.
     *
     * @param signed the signed manifest.
     * @param verifiers the key sets of the expected signers; at least one.
     * @return [Verification.Valid] if every verifier verifies a signature of the manifest.
     * @throws IllegalArgumentException if [verifiers] is empty.
     * @since 1.0.0
     */
    public suspend fun verifyAll(signed: SignedManifest, verifiers: List<KeysetVerifier>): Verification {
        require(verifiers.isNotEmpty()) { "At least one signer is expected" }
        val isValid = verifiers.all { verifier -> verify(signed, verifier).isValid }
        return Verification.of(isValid)
    }

    /**
     * Verifies that the signature [index] is a countersignature of [verifier] over the signature it names.
     *
     * Only the countersignature is checked, over the manifest and the bytes of the signature it names; whether that
     * signature itself is valid is not, so verify it with [verify] and the key set of its signer as well.
     *
     * @param signed the signed manifest.
     * @param index the countersignature.
     * @param verifier the key set of the expected countersigner.
     * @return [Verification.Valid] if it verifies.
     * @since 1.0.0
     */
    public suspend fun verifyCountersignature(
        signed: SignedManifest,
        index: Int,
        verifier: KeysetVerifier,
    ): Verification {
        val countersignature = signed.signatures.getOrNull(index)
        val target = countersignature?.countersigns?.let { position -> signed.signatures.getOrNull(position) }
            ?: return Verification.Invalid
        val message = counterPart(signed.manifest, target)
        return verifier.verify(data = message, signature = countersignature.signature)
    }

    /**
     * Encodes [signed] in DER.
     *
     * @param signed the signed manifest.
     * @return the encoding.
     * @since 1.0.0
     */
    public fun encode(signed: SignedManifest): ByteString = ManifestCodec.encodeSigned(signed)

    /**
     * Decodes a signed manifest that [encode] encoded.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the signed manifest, or [StreamFailure.Malformed].
     * @since 1.0.0
     */
    public fun decode(encoded: ByteString): Outcome<SignedManifest, StreamFailure> {
        val signed = ManifestCodec.decodeSignedOrNull(
            encoded,
            limits,
        ) ?: return Outcome.Failure(StreamFailure.Malformed)
        return Outcome.Success(signed)
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Manifests($limits)"

    private suspend fun isSignedBy(
        verifier: KeysetVerifier,
        message: ByteString,
        signature: ManifestSignature,
    ): Boolean {
        val verification = verifier.verify(data = message, signature = signature.signature)
        return verification.isValid
    }

    private fun signedPart(manifest: Manifest): ByteString =
        Octets.concat(Octets.utf8(SIGNATURE_LABEL), ManifestCodec.encode(manifest))

    private fun counterPart(manifest: Manifest, target: ManifestSignature): ByteString =
        Octets.concat(Octets.utf8(COUNTERSIGNATURE_LABEL), ManifestCodec.encode(manifest), target.signature)
}
