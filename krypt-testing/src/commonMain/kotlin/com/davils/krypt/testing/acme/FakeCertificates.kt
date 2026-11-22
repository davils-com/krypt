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

package com.davils.krypt.testing.acme

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.IdentifierType
import com.davils.krypt.acme.renewal.CertificateIdentifiers
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.request.CertificationRequests
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Instant

private const val UNUSED_REASON: Long = 7L
private const val HIGHEST_REASON: Long = 10L
private val REASONS: Set<Long> = (0L..HIGHEST_REASON).toSet() - UNUSED_REASON
private const val WINDOW_START_PARTS: Int = 2
private const val WINDOW_PARTS: Int = 3
private const val WINDOW_LENGTH_PARTS: Int = 6
private const val RENEWAL_RETRY_SECONDS: String = "21600"

internal class FakeCertificates(private val state: FakeState, private val orders: FakeOrders) {
    private val certificates = Certificates(state.crypto)
    private val requests = CertificationRequests(state.crypto)

    suspend fun finalize(request: SignedRequest, id: Int?): FakeReply {
        val record = state.found(state.orders, id)
        val order = orders.owned(record = record, owner = { found -> found.accountId }, request = request)
        val type = AcmeProblemType.OrderNotReady
        refuseUnless(condition = order.status == FakeOrders.READY, type = type, status = FakeReply.FORBIDDEN)
        val der = bytesOf(request.body.textOf(CSR))
        val csr = present(value = requests.decode(der).getOrNull(), type = AcmeProblemType.BadCsr)
        val publicKey = present(value = csr.publicKey, type = AcmeProblemType.BadCsr)
        val names = csr.requestedExtensions.subjectAlternativeNames
        val isMatching = names.toSet() == order.identifiers.map { identifier -> nameOf(identifier) }.toSet()
        refuseUnless(condition = isMatching, type = AcmeProblemType.BadCsr)
        refuseUnless(condition = requests.verify(csr).isValid, type = AcmeProblemType.BadCsr)
        val (chain, alternate) = state.issuer.issue(
            publicKey = publicKey,
            names = names,
            notBefore = timeOf(order.notBefore),
            notAfter = timeOf(order.notAfter),
        )
        val certificateId = state.nextId()
        state.certificates[certificateId] = FakeCertificate(
            id = certificateId,
            accountId = order.accountId,
            identifier = present(CertificateIdentifiers.of(chain.first())),
            chain = chain,
            alternate = alternate,
        )
        val polls = state.processingPolls
        val status = when (polls > 0) {
            true -> FakeOrders.PROCESSING
            false -> FakeOrders.VALID
        }
        val updated = order.copy(status = status, certificateId = certificateId, polls = polls)
        state.orders[order.id] = updated
        return FakeReply.json(json = orders.orderJson(updated), location = orders.orderUrl(order.id))
    }

    fun certificate(request: SignedRequest, segments: List<String>): FakeReply {
        val record = state.found(state.certificates, FakeRouter.idOf(segments))
        val certificate = orders.owned(record = record, owner = { found -> found.accountId }, request = request)
        val isAlternate = segments.getOrNull(2) == ALTERNATE
        val chain = when (isAlternate) {
            true -> certificate.alternate
            false -> certificate.chain
        }
        val url = orders.certificateUrl(certificate.id)
        val link = listOfNotNull((LINK to "<$url/$ALTERNATE>;rel=\"$ALTERNATE\"").takeIf { !isAlternate })
        return FakeReply(
            status = FakeReply.OK,
            body = chain.joinToString(separator = "") { found -> certificates.encodePem(found) }.encodeToByteString(),
            headers = listOf(FakeReply.CONTENT_TYPE to PEM_CHAIN) + link,
        )
    }

    fun revoke(request: SignedRequest): FakeReply {
        val payload = present(request.payload)
        val der = bytesOf(payload.textOf(CERTIFICATE))
        val found = state.certificates.values.firstOrNull { record -> record.chain.first().encoded == der }
        val certificate = present(value = found, status = FakeReply.NOT_FOUND)
        val owner = request.accountId ?: request.key
        val expected = when (request.isByKey) {
            true -> certificate.chain.first().publicKey
            false -> certificate.accountId
        }
        refuseUnless(condition = owner == expected, type = AcmeProblemType.Unauthorized)
        val reason = payload.longOf(REASON) ?: 0L
        refuseUnless(condition = reason in REASONS, type = AcmeProblemType.BadRevocationReason)
        refuseUnless(condition = !certificate.isRevoked, type = AcmeProblemType.AlreadyRevoked)
        state.certificates[certificate.id] = certificate.copy(isRevoked = true)
        return FakeReply(status = FakeReply.OK)
    }

    fun renewal(segments: List<String>): FakeReply {
        val identifier = segments.getOrNull(1)
        val found = state.certificates.values.firstOrNull { record -> record.identifier == identifier }
        val certificate = present(value = found, status = FakeReply.NOT_FOUND)
        val leaf = certificate.chain.first()
        val lifetime = leaf.notAfter - leaf.notBefore
        val start = leaf.notBefore + lifetime * WINDOW_START_PARTS / WINDOW_PARTS
        val end = start + lifetime / WINDOW_LENGTH_PARTS
        val window = json(START to text(start.toString()), END to text(end.toString()))
        val body = json(WINDOW to window, EXPLANATION to text(state.url(kind = "renewal-explained")))
        val reply = FakeReply.json(body)
        return reply.copy(headers = reply.headers + (FakeOrders.RETRY_AFTER to RENEWAL_RETRY_SECONDS))
    }

    private fun bytesOf(text: String?): ByteString {
        val decoded = Base64.decode(text = text.orEmpty(), alphabet = Base64Alphabet.Url, padding = false)
        return present(decoded.getOrNull())
    }

    private fun timeOf(text: String?): Instant? = text?.let { found -> Instant.parse(found) }

    private fun nameOf(identifier: AcmeIdentifier): GeneralName? = when (identifier.type) {
        IdentifierType.Dns -> GeneralName.Dns(identifier.value)
        IdentifierType.Ip -> GeneralName.IpAddress.parseOrNull(identifier.value)
    }

    private companion object {
        const val CSR: String = "csr"
        const val CERTIFICATE: String = "certificate"
        const val REASON: String = "reason"
        const val ALTERNATE: String = "alternate"
        const val LINK: String = "Link"
        const val PEM_CHAIN: String = "application/pem-certificate-chain"
        const val START: String = "start"
        const val END: String = "end"
        const val WINDOW: String = "suggestedWindow"
        const val EXPLANATION: String = "explanationURL"
    }
}
