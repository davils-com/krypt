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

package com.davils.krypt.ct

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.Der
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.ct.internal.LogChecks
import com.davils.krypt.ct.internal.LogParts
import com.davils.krypt.ct.internal.ResultParts
import com.davils.krypt.ct.internal.SctCodec
import com.davils.krypt.ct.internal.SignedData
import com.davils.krypt.ct.internal.VerdictParts
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val MAXIMUM_OPERATOR_LENGTH: Int = 256

/**
 * Certificate Transparency by RFC 6962: reads signed certificate timestamps from certificates, TLS and OCSP, verifies
 * them against the logs the application trusts and judges a certificate by a [CtPolicy].
 *
 * Every timestamp is read within [limits]; malformed input is refused, never truncated. A timestamp of a version other
 * than 1 is skipped, as RFC 6962 asks. Signatures are verified only with SHA-256 and ECDSA or RSA, and only as the
 * crypto policy of the environment permits. The log list is the caller's: krypt fetches nothing. Instances are
 * immutable and safe to share between threads.
 *
 * @param crypto the crypto facade that hashes and verifies.
 * @property limits the limits of reading timestamps.
 * @constructor Reads and verifies with [crypto] within [limits].
 * @since 1.0.0
 */
public class Transparency(private val crypto: Crypto, public val limits: CtLimits = CtLimits.Default) {
    /**
     * Creates a log from its public key, deriving the id as the SHA-256 digest of the key.
     *
     * @param publicKey the key that signs the timestamps of the log.
     * @param operator the organization that operates the log, 1 to 256 characters.
     * @param usableFrom since when timestamps of the log count, or null for always.
     * @param usableUntil until when, exclusive, timestamps of the log count, or null.
     * @return the log.
     * @throws IllegalArgumentException if [operator] is blank or too long, or [usableUntil] is not after [usableFrom].
     * @since 1.0.0
     */
    public suspend fun log(
        publicKey: PublicKey,
        operator: String,
        usableFrom: Instant? = null,
        usableUntil: Instant? = null,
    ): CtLog {
        require(operator.isNotBlank() && operator.length <= MAXIMUM_OPERATOR_LENGTH) {
            "An operator has 1 to $MAXIMUM_OPERATOR_LENGTH characters"
        }
        val start = usableFrom ?: Instant.DISTANT_PAST
        val end = usableUntil ?: Instant.DISTANT_FUTURE
        require(start < end) { "A log is usable until after it is usable from" }
        val logId = crypto.digests.digest(
            data = publicKey.encoded,
            algorithm = DigestAlgorithm.Sha256,
            use = AlgorithmUse.Verify,
        )
        val parts = LogParts(
            logId = logId,
            publicKey = publicKey,
            operator = operator,
            usableFrom = usableFrom,
            usableUntil = usableUntil,
        )
        return CtLog(parts)
    }

    /**
     * Reads a list of timestamps in its TLS encoding, as the TLS extension signed_certificate_timestamp sends it.
     *
     * @param encoded the encoded list.
     * @return the timestamps of version 1, or why the list was refused.
     * @since 1.0.0
     */
    public fun decodeList(encoded: ByteString): Outcome<List<SignedCertificateTimestamp>, CtFailure> =
        SctCodec.decodeList(encoded, limits)

    /**
     * Encodes a list of timestamps in its TLS encoding.
     *
     * @param timestamps the timestamps, at least one.
     * @return the encoded list.
     * @throws IllegalArgumentException if [timestamps] is empty or the list exceeds 65535 bytes.
     * @since 1.0.0
     */
    public fun encodeList(timestamps: List<SignedCertificateTimestamp>): ByteString {
        require(timestamps.isNotEmpty()) { "A list holds at least one timestamp" }
        return SctCodec.encodeList(timestamps)
    }

    /**
     * Returns the X.509 extension that embeds [timestamps] in a certificate, for a certificate authority.
     *
     * @param timestamps the timestamps, at least one.
     * @return the non-critical extension 1.3.6.1.4.1.11129.2.4.2.
     * @throws IllegalArgumentException if [timestamps] is empty or the list exceeds 65535 bytes.
     * @since 1.0.0
     */
    public fun extension(timestamps: List<SignedCertificateTimestamp>): Extension {
        val list = encodeList(timestamps)
        return Extension(ExtensionIds.SignedCertificateTimestamps, false, Der.encode { octetString(list) })
    }

    /**
     * Reads the timestamps embedded in [certificate].
     *
     * @param certificate the certificate.
     * @return the timestamps, empty if the certificate embeds none, or why the extension was refused.
     * @since 1.0.0
     */
    public fun embedded(certificate: Certificate): Outcome<List<SignedCertificateTimestamp>, CtFailure> {
        val extension = certificate.extensions.all.firstOrNull { found ->
            found.id == ExtensionIds.SignedCertificateTimestamps
        }
        return extension?.let { found -> wrapped(found.value) } ?: Outcome.Success(emptyList())
    }

    /**
     * Reads the timestamps of the OCSP single response extension 1.3.6.1.4.1.11129.2.4.5.
     *
     * @param extensionValue the value of the extension, an OCTET STRING that holds the list.
     * @return the timestamps, or why the extension was refused.
     * @since 1.0.0
     */
    public fun fromOcsp(extensionValue: ByteString): Outcome<List<SignedCertificateTimestamp>, CtFailure> =
        wrapped(extensionValue)

    /**
     * Verifies one timestamp of [certificate].
     *
     * For an [SctOrigin.Embedded] timestamp the log signed the precertificate: the certificate without its timestamps,
     * bound to the key of [issuer].
     *
     * @param timestamp the timestamp.
     * @param origin where it came from.
     * @param certificate the certificate it is for.
     * @param issuer the certificate of the issuer of [certificate].
     * @param logs the logs the application trusts.
     * @param at the time of validation; the clock of the environment by default.
     * @return the result.
     * @since 1.0.0
     */
    public suspend fun verify(
        timestamp: SignedCertificateTimestamp,
        origin: SctOrigin,
        certificate: Certificate,
        issuer: Certificate,
        logs: LogList,
        at: Instant? = null,
    ): SctResult {
        val time = at ?: crypto.environment.clock.now()
        val log = logs.find(timestamp.logId)
        val status = log?.let { found ->
            statusOf(
                timestamp = timestamp,
                origin = origin,
                certificate = certificate,
                issuer = issuer,
                log = found,
                at = time,
            )
        }
        val parts = ResultParts(
            timestamp = timestamp,
            origin = origin,
            log = log,
            status = status ?: SctStatus.UnknownLog,
        )
        return SctResult(parts)
    }

    /**
     * Reads every timestamp of [certificate], from the certificate, TLS and OCSP, verifies each one and judges the
     * certificate by [policy].
     *
     * Only valid timestamps of distinct logs count, and a log counts once however many timestamps it gave.
     *
     * @param certificate the certificate.
     * @param issuer the certificate of its issuer.
     * @param logs the logs the application trusts.
     * @param policy how many logs and operators the certificate needs; [CtPolicy.Default] by default.
     * @param tls the TLS encoded list of the TLS extension signed_certificate_timestamp, or null.
     * @param ocsp the value of the OCSP single response extension, or null.
     * @param at the time of validation; the clock of the environment by default.
     * @return the verdict, or why a list of timestamps was refused.
     * @since 1.0.0
     */
    public suspend fun check(
        certificate: Certificate,
        issuer: Certificate,
        logs: LogList,
        policy: CtPolicy = CtPolicy.Default,
        tls: ByteString? = null,
        ocsp: ByteString? = null,
        at: Instant? = null,
    ): Outcome<CtVerdict, CtFailure> {
        val sources = listOf(
            SctOrigin.Embedded to embedded(certificate),
            SctOrigin.Tls to tls?.let { encoded -> decodeList(encoded) },
            SctOrigin.Ocsp to ocsp?.let { value -> fromOcsp(value) },
        )
        val failure = sources.firstNotNullOfOrNull { (_, outcome) -> outcome?.failureOrNull() }
        if (failure != null) return Outcome.Failure(failure)
        val time = at ?: crypto.environment.clock.now()
        val found = sources.flatMap { (origin, outcome) ->
            val timestamps = outcome?.getOrNull().orEmpty()
            timestamps.map { timestamp -> origin to timestamp }
        }
        val results = found.map { (origin, timestamp) ->
            verify(
                timestamp = timestamp,
                origin = origin,
                certificate = certificate,
                issuer = issuer,
                logs = logs,
                at = time,
            )
        }
        val valid = LogChecks.validLogs(results)
        val operatorNames = valid.map { log -> log.operator }
        val operators = operatorNames.toSet().size
        val required = LogChecks.required(certificate, policy)
        val compliance = LogChecks.compliance(
            required = required,
            logs = valid.size,
            operators = operators,
            policy = policy,
        )
        val parts = VerdictParts(
            compliance = compliance,
            results = results,
            required = required,
            logs = valid.size,
            operators = operators,
        )
        val verdict = CtVerdict(parts)
        return Outcome.Success(verdict)
    }

    private fun wrapped(value: ByteString): Outcome<List<SignedCertificateTimestamp>, CtFailure> {
        val list = Der.decodeOrNull(value) { readOctetString() } ?: return Outcome.Failure(CtFailure.Malformed)
        return decodeList(list)
    }

    private suspend fun statusOf(
        timestamp: SignedCertificateTimestamp,
        origin: SctOrigin,
        certificate: Certificate,
        issuer: Certificate,
        log: CtLog,
        at: Instant,
    ): SctStatus {
        val refusal = listOf(
            SctStatus.FutureTimestamp.takeIf { timestamp.timestamp > at },
            SctStatus.LogNotUsable.takeIf { !log.isUsableAt(timestamp.timestamp) },
        )
        val refused = refusal.firstNotNullOfOrNull { status -> status }
        val algorithm = LogChecks.permitted(crypto = crypto, algorithm = timestamp.algorithm, key = log.publicKey)
        val signed = algorithm?.takeIf { refused == null }?.let { permitted ->
            val data = SignedData.of(
                crypto = crypto,
                timestamp = timestamp,
                origin = origin,
                certificate = certificate,
                issuer = issuer,
            )
            val verification = crypto.signatures.verify(
                key = log.publicKey,
                data = data,
                signature = timestamp.signature,
                algorithm = permitted,
            )
            listOf(SctStatus.InvalidSignature, SctStatus.Valid)[verification.isValid.compareTo(false)]
        }
        return refused ?: signed ?: SctStatus.AlgorithmNotPermitted
    }
}
