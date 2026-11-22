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

package com.davils.krypt.acme.renewal

import com.davils.krypt.acme.internal.base64Url
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * The certificate identifiers of RFC 9773 section 4.1, which name a certificate in the renewal information and in
 * the `replaces` member of a new order.
 *
 * @since 1.0.0
 */
public object CertificateIdentifiers {
    /**
     * Returns the identifier of [certificate]: the base64url of the key identifier of its authority key identifier
     * extension, a period and the base64url of the content octets of the DER encoding of its serial number.
     *
     * @param certificate the certificate.
     * @return the identifier, or null if the certificate carries no authority key identifier with a key identifier.
     * @since 1.0.0
     */
    public fun of(certificate: Certificate): String? {
        val authorityKeyIdentifier = certificate.extensions.authorityKeyIdentifier
        val keyIdentifier = authorityKeyIdentifier?.keyIdentifier ?: return null
        return of(keyIdentifier = keyIdentifier, serialNumber = certificate.serialNumber)
    }

    /**
     * Returns the identifier of a certificate with the authority key identifier [keyIdentifier] and the serial
     * number [serialNumber].
     *
     * @param keyIdentifier the key identifier of the authority key identifier extension.
     * @param serialNumber the serial number.
     * @return the identifier.
     * @throws IllegalArgumentException if [keyIdentifier] is empty.
     * @since 1.0.0
     */
    public fun of(keyIdentifier: ByteString, serialNumber: DerInteger): String {
        require(keyIdentifier.size > 0) { "A key identifier has at least one byte" }
        return "${base64Url(keyIdentifier)}.${base64Url(serialNumber.bytes)}"
    }
}
