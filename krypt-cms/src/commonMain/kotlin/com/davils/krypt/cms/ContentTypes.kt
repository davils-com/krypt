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

package com.davils.krypt.cms

import com.davils.krypt.asn1.ObjectIdentifier

/**
 * The content types of CMS that krypt reads and writes.
 *
 * @since 1.0.0
 */
public object ContentTypes {
    /**
     * id-data of RFC 5652: arbitrary octets.
     *
     * @since 1.0.0
     */
    public val Data: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.1")

    /**
     * id-signedData of RFC 5652.
     *
     * @since 1.0.0
     */
    public val SignedData: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.2")

    /**
     * id-envelopedData of RFC 5652.
     *
     * @since 1.0.0
     */
    public val EnvelopedData: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.3")

    /**
     * id-encryptedData of RFC 5652.
     *
     * @since 1.0.0
     */
    public val EncryptedData: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.6")

    /**
     * id-ct-authEnvelopedData of RFC 5083.
     *
     * @since 1.0.0
     */
    public val AuthEnvelopedData: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.1.23")

    /**
     * id-ct-TSTInfo of RFC 3161: the content of a time-stamp token.
     *
     * @since 1.0.0
     */
    public val TstInfo: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.1.4")
}
