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

package com.davils.krypt.authority

/**
 * Why a certificate authority refused to revoke a certificate.
 *
 * @since 1.0.0
 */
public enum class RevocationFailure {
    /**
     * The authority did not issue a certificate with this serial number.
     *
     * @since 1.0.0
     */
    UnknownCertificate,

    /**
     * The certificate is already revoked; a revocation is final.
     *
     * @since 1.0.0
     */
    AlreadyRevoked,

    /**
     * The reason is not one a revocation may carry: a hold and its removal are not supported, because a
     * revocation is final.
     *
     * @since 1.0.0
     */
    ReasonNotPermitted,

    /**
     * The repository of the application failed; the revocation may not have been recorded.
     *
     * @since 1.0.0
     */
    RepositoryUnavailable,
}
