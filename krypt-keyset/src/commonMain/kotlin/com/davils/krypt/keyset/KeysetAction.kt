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

package com.davils.krypt.keyset

import com.davils.krypt.core.audit.AuditAction

/**
 * What happened to a key set, as told by a [KeysetEvent] and recorded in the audit trail.
 *
 * @property audit the action in the audit trail.
 * @since 1.0.0
 */
public enum class KeysetAction(public val audit: AuditAction) {
    /**
     * A new key set was generated with its first key.
     *
     * @since 1.0.0
     */
    Generated(AuditAction("keyset.generate")),

    /**
     * A new key became the primary key.
     *
     * @since 1.0.0
     */
    Rotated(AuditAction("keyset.rotate")),

    /**
     * A new key was added beside the primary key.
     *
     * @since 1.0.0
     */
    Added(AuditAction("keyset.add")),

    /**
     * An existing key became the primary key.
     *
     * @since 1.0.0
     */
    Promoted(AuditAction("keyset.promote")),

    /**
     * A disabled key was enabled again.
     *
     * @since 1.0.0
     */
    Enabled(AuditAction("keyset.enable")),

    /**
     * A key was disabled.
     *
     * @since 1.0.0
     */
    Disabled(AuditAction("keyset.disable")),

    /**
     * The material of a key was wiped.
     *
     * @since 1.0.0
     */
    Destroyed(AuditAction("keyset.destroy")),
}
