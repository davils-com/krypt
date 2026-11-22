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

package com.davils.krypt.stream

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.map
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.ByteLimitException
import com.davils.krypt.core.io.ByteSink
import com.davils.krypt.core.io.ByteSource
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.stream.internal.Chunks
import com.davils.krypt.stream.internal.Header
import com.davils.krypt.stream.internal.HeaderCodec
import com.davils.krypt.stream.internal.KeySchedule
import com.davils.krypt.stream.internal.MerkleTree
import com.davils.krypt.stream.internal.Octets
import com.davils.krypt.stream.internal.RandomAccessByteSource
import com.davils.krypt.stream.internal.SegmentCipher
import com.davils.krypt.stream.internal.SegmentWalk
import com.davils.krypt.stream.internal.StreamRefusal
import com.davils.krypt.stream.internal.Unlocked
import com.davils.krypt.stream.internal.Unlocking
import com.davils.krypt.stream.internal.Wrapping
import kotlinx.io.bytestring.ByteString

private const val DEFAULT_SEGMENT_SIZE: Int = 65_536

/**
 * Encrypts bulk data of any size into containers of the format `KRYPT/1` and reads them back, as a stream or at any
 * offset.
 *
 * A container starts with a header: the magic `KRYPT`, the version, the [StreamSuite], the segment size, a random
 * salt and nonce prefix, one entry per [Recipient] that holds the data key encrypted for it, a key commitment and a
 * MAC over the whole header. The data key is fresh for every container; HKDF derives from it, the salt, the header
 * and the digest of the associated data the key of the segments, the commitment and the key of the MAC, so the
 * header and the associated data are bound to every segment and a data key that opens one recipient but not another
 * is refused. The segments follow the STREAM construction: each segment is sealed with a nonce of the prefix, its
 * index and a flag for the last segment, so truncation, reordering and appended data are detected.
 *
 * Before any key is unwrapped, decryption asks the crypto policy whether it permits the suite of the container and
 * the platform whether it offers it; a container of a forbidden suite is [StreamFailure.Refused] and one of a missing
 * suite [StreamFailure.Unsupported], never thrown.
 *
 * Decryption writes the plaintext of every segment as soon as it is authentic. When it fails at a later segment, the
 * plaintext written so far must be discarded: only a [Outcome.Success] vouches for the whole container.
 *
 * The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives.
 * @property limits the limits of containers.
 * @since 1.0.0
 */
public class Containers(public val crypto: Crypto, public val limits: StreamLimits = StreamLimits.Default) {
    /**
     * Encrypts everything [source] holds into [sink].
     *
     * @param source the plaintext.
     * @param sink where the container goes.
     * @param recipients who can open the container; at least one.
     * @param associatedData authenticated context that must be given again to decrypt; empty by default.
     * @param suite the AEAD of the segments; AES-256-GCM by default.
     * @param segmentSize the size of a segment of plaintext, 4 KiB to 8 MiB; 64 KiB by default.
     * @return the seal of the container, for signing it.
     * @throws IllegalArgumentException if there are no or too many recipients or [segmentSize] is out of range.
     * @throws ByteLimitException if the plaintext needs more segments than the limits allow.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        source: ByteSource,
        sink: ByteSink,
        recipients: List<Recipient>,
        associatedData: ByteString = ByteString(),
        suite: StreamSuite = StreamSuite.Aes256Gcm,
        segmentSize: Int = DEFAULT_SEGMENT_SIZE,
    ): ContainerSeal {
        require(recipients.size in 1..limits.maximumRecipients) {
            "A container has 1 to ${limits.maximumRecipients} recipients"
        }
        require(segmentSize in HeaderCodec.MINIMUM_SEGMENT..HeaderCodec.MAXIMUM_SEGMENT) {
            "A segment has ${HeaderCodec.MINIMUM_SEGMENT} to ${HeaderCodec.MAXIMUM_SEGMENT} bytes"
        }
        val random = crypto.environment.random
        val salt = ByteString(random.bytes(HeaderCodec.SALT_BYTES))
        val prefix = ByteString(random.bytes(HeaderCodec.PREFIX_BYTES))
        val core = HeaderCodec.core(suite = suite, segmentSize = segmentSize, salt = salt, prefix = prefix)
        val dataKey = SecretBytes.random(size = KeySchedule.DATA_KEY_BYTES, random = random)
        val wrapping = Wrapping(crypto, limits)
        val wrapContext = Octets.concat(KeySchedule.RECIPIENT_LABEL, core)
        val context = KeySchedule.context(crypto = crypto, core = core, associatedData = associatedData)
        val (entries, schedule) = dataKey.use { secret ->
            val wrapped = recipients.map { recipient ->
                wrapping.wrap(recipient = recipient, dataKey = secret, context = wrapContext)
            }
            wrapped to KeySchedule.derive(
                crypto = crypto,
                dataKey = secret,
                salt = salt,
                context = context,
                suite = suite,
            )
        }
        return try {
            val unsigned = Header(
                suite = suite,
                segmentSize = segmentSize,
                salt = salt,
                noncePrefix = prefix,
                recipients = entries,
                commitment = schedule.commitment,
                mac = ByteString(),
            )
            val mac = crypto.macs.mac(
                key = schedule.macKey,
                data = unsigned.authenticated,
                algorithm = MacAlgorithm.HmacSha256,
            )
            val header = unsigned.copy(mac = mac)
            val cipher = SegmentCipher(crypto = crypto, suite = suite, key = schedule.payload, prefix = prefix)
            writeSegments(source = source, sink = sink, header = header, cipher = cipher)
        } finally {
            schedule.destroy()
        }
    }

    /**
     * Decrypts the container [source] holds into [sink].
     *
     * @param source the container, possibly from an attacker.
     * @param sink where the plaintext goes; discard it unless the result is a success.
     * @param credentials what may open a recipient, tried in order.
     * @param associatedData the authenticated context the container was encrypted with.
     * @return the seal of the container, or why it could not be decrypted.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        source: ByteSource,
        sink: ByteSink,
        credentials: List<Credential>,
        associatedData: ByteString = ByteString(),
    ): Outcome<ContainerSeal, StreamFailure> = attempt {
        val header = HeaderCodec.read(source, limits)
        val unlocked = Unlocking(
            crypto,
            limits,
        ).unlock(header = header, credentials = credentials, associatedData = associatedData)
        try {
            var plaintextBytes = 0L
            val walk = SegmentWalk(crypto, limits)
            walk.walk(source, header) { index, isLast, segment ->
                val plaintext = unlocked.cipher.open(index = index, isLast = isLast, ciphertext = segment)
                    ?: StreamRefusal.refuse(StreamFailure.DecryptionFailed)
                sink.write(source = plaintext.toByteArray(), offset = 0, length = plaintext.size)
                plaintextBytes += plaintext.size
            }
            sealOf(header = header, walk = walk, plaintextBytes = plaintextBytes)
        } finally {
            unlocked.destroy()
        }
    }

    /**
     * Opens the container [source] holds for reading at any offset.
     *
     * The header is authenticated now; every segment is authenticated when it is read.
     *
     * @param source the container, possibly from an attacker.
     * @param credentials what may open a recipient, tried in order.
     * @param associatedData the authenticated context the container was encrypted with.
     * @return the reader, which the caller closes, or why the container could not be opened.
     * @since 1.0.0
     */
    public suspend fun open(
        source: RandomAccessSource,
        credentials: List<Credential>,
        associatedData: ByteString = ByteString(),
    ): Outcome<ContainerReader, StreamFailure> = attempt {
        val bytes = RandomAccessByteSource(source)
        val header = HeaderCodec.read(bytes, limits)
        val tag = header.suite.aead.tagBytes
            .toLong()
        val chunk = header.segmentSize + tag
        val body = source.size - bytes.position
        val segments = (body + chunk - 1).coerceAtLeast(0L) / chunk
        val lastSize = body - (segments - 1) * chunk
        StreamRefusal.ensure(
            body >= tag && lastSize >= tag && segments <= limits.maximumSegments,
            StreamFailure.Malformed,
        )
        val unlocked = Unlocking(
            crypto,
            limits,
        ).unlock(header = header, credentials = credentials, associatedData = associatedData)
        ContainerReader(
            source = source,
            unlocked = unlocked,
            dataStart = bytes.position,
            segmentSize = header.segmentSize,
            segments = segments,
            plaintextBytes = (segments - 1) * header.segmentSize + lastSize - tag,
        )
    }

    /**
     * Reads the seal of the container [source] holds without its keys, to verify a signature of its manifest.
     *
     * @param source the container, possibly from an attacker.
     * @return the seal, or why the bytes are not a container.
     * @since 1.0.0
     */
    public suspend fun inspect(source: ByteSource): Outcome<ContainerSeal, StreamFailure> = attempt {
        val header = HeaderCodec.read(source, limits)
        val tag = header.suite.aead.tagBytes
        var plaintextBytes = 0L
        val walk = SegmentWalk(crypto, limits)
        walk.walk(source, header) { _, _, segment -> plaintextBytes += segment.size - tag }
        sealOf(header = header, walk = walk, plaintextBytes = plaintextBytes)
    }

    /**
     * Wraps the data key of the container [source] holds for new [recipients] and writes the container into [sink],
     * without encrypting the data again: the segments are authenticated and copied as they are.
     *
     * This is how a container moves to the new primary key of a key set after a rotation, or gets another reader.
     * The data key stays the same, so a recipient that was removed but kept the data key can still read the copy;
     * encrypt the data again when a key was compromised.
     *
     * @param source the container, possibly from an attacker.
     * @param sink where the rewrapped container goes; discard it unless the result is a success.
     * @param credentials what may open a recipient of the container now.
     * @param recipients who can open the rewrapped container; at least one.
     * @param associatedData the authenticated context the container was encrypted with.
     * @return the seal of the rewrapped container, or why the container could not be read.
     * @throws IllegalArgumentException if there are no or too many recipients.
     * @since 1.0.0
     */
    public suspend fun rewrap(
        source: ByteSource,
        sink: ByteSink,
        credentials: List<Credential>,
        recipients: List<Recipient>,
        associatedData: ByteString = ByteString(),
    ): Outcome<ContainerSeal, StreamFailure> {
        require(recipients.size in 1..limits.maximumRecipients) {
            "A container has 1 to ${limits.maximumRecipients} recipients"
        }
        return attempt {
            val header = HeaderCodec.read(source, limits)
            val unlocking = Unlocking(crypto, limits)
            val unlocked = unlocking.unlock(header = header, credentials = credentials, associatedData = associatedData)
            try {
                val rewrapped = rewrapped(unlocked = unlocked, recipients = recipients)
                copySegments(source = source, sink = sink, unlocked = unlocked, header = rewrapped)
            } finally {
                unlocked.destroy()
            }
        }
    }

    /**
     * Encrypts [plaintext] held in memory into a container.
     *
     * @param plaintext the plaintext.
     * @param recipients who can open the container.
     * @param associatedData authenticated context; empty by default.
     * @return the container.
     * @throws IllegalArgumentException if there are no or too many recipients.
     * @since 1.0.0
     */
    public suspend fun encrypt(
        plaintext: ByteString,
        recipients: List<Recipient>,
        associatedData: ByteString = ByteString(),
    ): ByteString {
        val sink = BufferSink(Int.MAX_VALUE)
        encrypt(
            source = plaintext.asByteSource(),
            sink = sink,
            recipients = recipients,
            associatedData = associatedData,
        )
        return sink.toByteString()
    }

    /**
     * Decrypts a container held in memory.
     *
     * @param container the container, possibly from an attacker.
     * @param credentials what may open a recipient.
     * @param associatedData the authenticated context.
     * @return the plaintext, or why it could not be decrypted.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        container: ByteString,
        credentials: List<Credential>,
        associatedData: ByteString = ByteString(),
    ): Outcome<ByteString, StreamFailure> {
        val sink = BufferSink(container.size)
        val result = decrypt(
            source = container.asByteSource(),
            sink = sink,
            credentials = credentials,
            associatedData = associatedData,
        )
        val plaintext = result.map { _ -> sink.toByteString() }
        sink.wipe()
        return plaintext
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Containers($limits)"

    private suspend fun writeSegments(
        source: ByteSource,
        sink: ByteSink,
        header: Header,
        cipher: SegmentCipher,
    ): ContainerSeal {
        val encoded = header.encoded
        sink.write(source = encoded.toByteArray(), offset = 0, length = encoded.size)
        val tree = MerkleTree(crypto, DigestAlgorithm.Sha256)
        val chunks = Chunks(source, header.segmentSize)
        var plaintextBytes = 0L
        var ciphertextBytes = encoded.size.toLong()
        var chunk = chunks.nextOrNull()
        while (chunk != null) {
            if (tree.leaves >= limits.maximumSegments) {
                throw ByteLimitException(
                    limits.maximumSegments * header.segmentSize,
                )
            }
            val (plaintext, isLast) = chunk
            val sealed = cipher.seal(index = tree.leaves, isLast = isLast, plaintext = plaintext)
            sink.write(source = sealed.toByteArray(), offset = 0, length = sealed.size)
            tree.add(sealed)
            plaintextBytes += plaintext.size
            ciphertextBytes += sealed.size
            chunk = chunks.nextOrNull()
        }
        return ContainerSeal(
            headerDigest = crypto.digests.digest(encoded, DigestAlgorithm.Sha256),
            segmentSize = header.segmentSize,
            segments = tree.leaves,
            ciphertextBytes = ciphertextBytes,
            plaintextBytes = plaintextBytes,
            root = tree.root(),
        )
    }

    private suspend fun rewrapped(unlocked: Unlocked, recipients: List<Recipient>): Header {
        val header = unlocked.header
        val wrapping = Wrapping(crypto, limits)
        val context = Octets.concat(KeySchedule.RECIPIENT_LABEL, header.core)
        val entries = recipients.map { recipient ->
            wrapping.wrap(recipient = recipient, dataKey = unlocked.dataKey, context = context)
        }
        val unsigned = header.copy(recipients = entries, mac = ByteString())
        val mac = crypto.macs.mac(
            key = unlocked.schedule.macKey,
            data = unsigned.authenticated,
            algorithm = MacAlgorithm.HmacSha256,
        )
        return unsigned.copy(mac = mac)
    }

    private suspend fun copySegments(
        source: ByteSource,
        sink: ByteSink,
        unlocked: Unlocked,
        header: Header,
    ): ContainerSeal {
        val encoded = header.encoded
        sink.write(source = encoded.toByteArray(), offset = 0, length = encoded.size)
        var plaintextBytes = 0L
        val walk = SegmentWalk(crypto, limits)
        walk.walk(source, header) { index, isLast, segment ->
            val plaintext = unlocked.cipher.open(index = index, isLast = isLast, ciphertext = segment)
                ?: StreamRefusal.refuse(StreamFailure.DecryptionFailed)
            sink.write(source = segment.toByteArray(), offset = 0, length = segment.size)
            plaintextBytes += plaintext.size
        }
        return sealOf(header = header, walk = walk, plaintextBytes = plaintextBytes)
    }

    private suspend fun sealOf(header: Header, walk: SegmentWalk, plaintextBytes: Long): ContainerSeal {
        val encoded = header.encoded
        return ContainerSeal(
            headerDigest = crypto.digests.digest(encoded, DigestAlgorithm.Sha256),
            segmentSize = header.segmentSize,
            segments = walk.tree.leaves,
            ciphertextBytes = encoded.size + walk.ciphertextBytes,
            plaintextBytes = plaintextBytes,
            root = walk.tree.root(),
        )
    }

    private suspend fun <T> attempt(block: suspend () -> T): Outcome<T, StreamFailure> = try {
        Outcome.Success(block())
    } catch (refusal: StreamRefusal) {
        Outcome.Failure(refusal.failure)
    } catch (ignored: PolicyViolationException) {
        Outcome.Failure(StreamFailure.Refused)
    }
}
