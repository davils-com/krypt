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

package com.davils.krypt.spiffe.source

import com.davils.krypt.spiffe.x509.X509Svid

/**
 * Supplies the current X.509-SVID of the workload, such as from the Workload API. krypt opens no socket and speaks
 * no gRPC: the application implements this interface over the transport it chose; [X509Source] is an implementation
 * that holds what the application pushes.
 *
 * @since 1.0.0
 */
public fun interface SvidSource {
    /**
     * Returns the current SVID.
     *
     * @return the SVID, or null if the workload has none yet.
     * @since 1.0.0
     */
    public suspend fun svid(): X509Svid?
}
