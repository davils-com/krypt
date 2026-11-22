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

package com.davils.krypt.tls.trust

import java.security.cert.CertificateException

/**
 * Thrown by the trust manager of krypt when it refuses the certificate chain of a peer; JSSE wraps it into the
 * failure of the handshake, where [TrustFailure.of] finds it again.
 *
 * The message names only the [failure], never a field of a certificate.
 *
 * @property failure why the peer was refused.
 * @constructor Refuses a peer.
 * @since 1.0.0
 */
public class TrustRefusedException(public val failure: TrustFailure) :
    CertificateException("The peer is not trusted: $failure") {
    private companion object {
        private const val serialVersionUID: Long = 1L
    }
}
