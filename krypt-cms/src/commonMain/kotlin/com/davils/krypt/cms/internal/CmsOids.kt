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

package com.davils.krypt.cms.internal

import com.davils.krypt.asn1.ObjectIdentifier

internal object CmsOids {
    val CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.3")
    val MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.4")
    val SIGNING_TIME: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.5")
    val COUNTERSIGNATURE: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.6")
    val SIGNING_CERTIFICATE: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.2.12")
    val SIGNING_CERTIFICATE_V2: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.2.47")
    val TIME_STAMP_TOKEN: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.2.14")

    val RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.1")
    val RSAES_OAEP: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.7")
    val MGF1: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.8")
    val P_SPECIFIED: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.9")
    val EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.2.1")
    val X25519: ObjectIdentifier = ObjectIdentifier.of("1.3.101.110")
    val X448: ObjectIdentifier = ObjectIdentifier.of("1.3.101.111")

    val SHA1: ObjectIdentifier = ObjectIdentifier.of("1.3.14.3.2.26")
    val SHA256: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.1")
    val SHA384: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.2")
    val SHA512: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.3")
    val SHAKE256: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.2.12")

    val AES128_CBC: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.2")
    val AES256_CBC: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.42")
    val AES128_GCM: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.6")
    val AES256_GCM: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.46")
    val AES128_WRAP: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.5")
    val AES256_WRAP: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.1.45")

    val ECDH_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.3.132.1.11.1")
    val ECDH_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.3.132.1.11.2")
    val ECDH_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.3.132.1.11.3")
    val ECDH_COFACTOR_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.3.132.1.14.1")
    val ECDH_COFACTOR_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.3.132.1.14.2")
    val ECDH_COFACTOR_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.3.132.1.14.3")
    val HKDF_SCHEME_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.19")
    val HKDF_SCHEME_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.20")
    val HKDF_SCHEME_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.21")

    val HKDF_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.28")
    val HKDF_SHA384: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.29")
    val HKDF_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.30")
    val ML_KEM_768: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.4.2")
    val ML_KEM_1024: ObjectIdentifier = ObjectIdentifier.of("2.16.840.1.101.3.4.4.3")
    val ORI_KEM: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.13.3")

    val PBKDF2: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.5.12")
    val HMAC_SHA1: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.7")
    val HMAC_SHA256: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.9")
    val HMAC_SHA512: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.2.11")
    val PWRI_KEK: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.16.3.9")
}
