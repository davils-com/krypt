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

package com.davils.krypt.core.audit

/**
 * How an audited operation ended.
 *
 * @since 1.0.0
 */
public enum class AuditOutcome {
    /**
     * The operation did what it was asked to.
     *
     * @since 1.0.0
     */
    Succeeded,

    /**
     * The operation refused, such as a signing request the policy of an authority forbids.
     *
     * @since 1.0.0
     */
    Refused,

    /**
     * The operation failed, such as a key management service that could not be reached.
     *
     * @since 1.0.0
     */
    Failed,
}
