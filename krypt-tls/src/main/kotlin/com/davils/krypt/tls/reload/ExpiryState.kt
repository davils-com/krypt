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

package com.davils.krypt.tls.reload

/**
 * Where a certificate stands in its validity.
 *
 * @since 1.0.0
 */
public enum class ExpiryState {
    /**
     * The validity has not started yet.
     *
     * @since 1.0.0
     */
    NotYetValid,

    /**
     * The certificate is valid beyond the warning time.
     *
     * @since 1.0.0
     */
    Valid,

    /**
     * The certificate is valid but expires within the warning time.
     *
     * @since 1.0.0
     */
    Expiring,

    /**
     * The certificate has expired.
     *
     * @since 1.0.0
     */
    Expired,
}
