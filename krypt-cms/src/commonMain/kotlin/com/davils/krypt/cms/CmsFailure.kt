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

/**
 * Why krypt refused a CMS structure, a signature, a decryption or a time stamp.
 *
 * @since 1.0.0
 */
public enum class CmsFailure {
    /**
     * The encoding is not strict DER of the structure, breaks a limit of [CmsLimits], has another content type than
     * expected or uses a form krypt does not read, such as BER with indefinite lengths or an attribute certificate.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The crypto policy forbids an algorithm or a key, or krypt or the platform does not know it.
     *
     * @since 1.0.0
     */
    AlgorithmNotPermitted,

    /**
     * Detached signed data was verified without its content.
     *
     * @since 1.0.0
     */
    ContentMissing,

    /**
     * No certificate in the message or among those of the caller matches the identifier of the signer.
     *
     * @since 1.0.0
     */
    SignerNotFound,

    /**
     * The message-digest attribute, or the digest of a time-stamped message, differs from the content.
     *
     * @since 1.0.0
     */
    DigestMismatch,

    /**
     * The signature does not verify with the key of the signer's certificate.
     *
     * @since 1.0.0
     */
    BadSignature,

    /**
     * A signed attribute is missing, repeated or contradicts the message, such as a content-type attribute of another
     * type or a signing-certificate attribute that names another certificate.
     *
     * @since 1.0.0
     */
    AttributeMismatch,

    /**
     * The certificate of the signer does not lead to a trust anchor of the caller's path validator.
     *
     * @since 1.0.0
     */
    UntrustedSigner,

    /**
     * No recipient of the message matches the credential.
     *
     * @since 1.0.0
     */
    RecipientNotFound,

    /**
     * The message could not be decrypted: one failure for a wrong key, a wrong password, a wrong padding and a wrong
     * tag alike, so it reveals no oracle.
     *
     * @since 1.0.0
     */
    DecryptionFailed,

    /**
     * The time-stamp authority refused the request or sent no token.
     *
     * @since 1.0.0
     */
    TimeStampRejected,

    /**
     * The time-stamp token answers another request: its imprint, nonce or policy differs.
     *
     * @since 1.0.0
     */
    TimeStampMismatch,

    /**
     * The certificate of the time-stamp authority lacks the critical extended key usage id-kp-timeStamping as its
     * only purpose.
     *
     * @since 1.0.0
     */
    UnauthorizedTimeStampAuthority,
}
