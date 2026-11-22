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

package com.davils.krypt.ocsp.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.ocsp.CertId
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspFailure
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspParameters
import com.davils.krypt.ocsp.OcspRequest
import com.davils.krypt.ocsp.OcspResponse
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

internal class Scenario(val authority: Authority, val leaf: Certificate, private val engine: Ocsp = ocsp) {
    val issuer: OcspIssuer = authority.issuer

    suspend fun certId(algorithm: DigestAlgorithm = DigestAlgorithm.Sha256): CertId =
        engine.certId(certificate = leaf, issuer = issuer, algorithm = algorithm)

    suspend fun request(nonceBytes: Int? = null, algorithm: DigestAlgorithm = DigestAlgorithm.Sha256): OcspRequest =
        engine.request(listOf(certId(algorithm)), nonceBytes)

    fun decoded(encoded: ByteString): OcspResponse = checkNotNull(engine.decodeResponse(encoded).getOrNull())

    suspend fun verify(
        encoded: ByteString,
        request: OcspRequest? = null,
        parameters: OcspParameters = OcspParameters(),
    ): Outcome<SingleResponse, OcspFailure> = engine.verify(
        response = decoded(encoded),
        certificate = leaf,
        issuer = issuer,
        request = request,
        parameters = parameters,
    )

    suspend fun failureOf(encoded: ByteString, parameters: OcspParameters = OcspParameters()): OcspFailure? =
        verify(encoded = encoded, parameters = parameters).failureOrNull()

    companion object {
        suspend fun create(engine: Ocsp = ocsp): Scenario {
            val root = Authority.root()
            return Scenario(root, root.issue(LEAF).certificate, engine)
        }
    }
}
