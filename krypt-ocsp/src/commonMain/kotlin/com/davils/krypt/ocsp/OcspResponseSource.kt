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

package com.davils.krypt.ocsp

import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * Where an [OcspRevocationChecker] gets responses: the caller asks a responder over HTTP, or hands over a response
 * stapled to a TLS handshake.
 *
 * @since 1.0.0
 */
public fun interface OcspResponseSource {
    /**
     * Returns the response to [request] about [certificate].
     *
     * @param request the request, to send by [OcspEncodings].
     * @param certificate the certificate whose status is asked.
     * @param issuer its issuer.
     * @return the DER encoding of the response, or null if there is none.
     * @since 1.0.0
     */
    public suspend fun response(request: OcspRequest, certificate: Certificate, issuer: OcspIssuer): ByteString?

    /**
     * Sources of responses.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns a source that answers with [response] about [certificate] only, such as a response stapled to a
         * TLS handshake for the certificate of the peer.
         *
         * @param certificate the certificate the response is about.
         * @param response the DER encoding of the response.
         * @return the source.
         * @since 1.0.0
         */
        public fun stapled(certificate: Certificate, response: ByteString): OcspResponseSource =
            OcspResponseSource { _, asked, _ -> response.takeIf { asked == certificate } }
    }
}
