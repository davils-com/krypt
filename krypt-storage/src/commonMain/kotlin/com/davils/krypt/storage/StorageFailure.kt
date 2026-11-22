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

package com.davils.krypt.storage

/**
 * Why stored data could not be read.
 *
 * @since 1.0.0
 */
public enum class StorageFailure {
    /**
     * Nothing is stored under the name.
     *
     * @since 1.0.0
     */
    Missing,

    /**
     * The stored bytes are not an object of krypt.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The object is not the version the ledger records: an old or deleted version was put back, under any blinded
     * key of its name, the ledger has no record of the name, or a write failed after its version was recorded.
     *
     * @since 1.0.0
     */
    Rollback,

    /**
     * The object was changed, moved from another name, or its keys are gone.
     *
     * @since 1.0.0
     */
    DecryptionFailed,

    /**
     * The store or the ledger of the application failed, or another process changed the object at the same time;
     * the failure itself is not passed on.
     *
     * @since 1.0.0
     */
    Unavailable,
}
