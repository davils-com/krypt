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
 * Where krypt reports the security relevant things it does, such as generating, rotating or destroying a key,
 * issuing or revoking a certificate or shredding data; the caller implements it over its own audit trail.
 *
 * krypt never writes an audit trail itself. A sink should append to a store the application cannot rewrite. Whether a
 * failing sink stops the operation is decided by [com.davils.krypt.core.Environment.isAuditRequired]: a required audit
 * refuses an operation it could not record, which a certificate authority wants; a best-effort audit counts the
 * failure and carries on.
 *
 * @since 1.0.0
 */
public fun interface AuditSink {
    /**
     * Records [entry].
     *
     * @param entry what happened.
     * @since 1.0.0
     */
    public suspend fun record(entry: AuditEntry)
}
