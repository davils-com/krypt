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

package com.davils.krypt.tls.peer

/**
 * Builds a [PeerPolicy].
 *
 * @param configure the rules.
 * @return the policy.
 * @throws com.davils.kore.core.validation.report.ValidationException if a rule is blank, too long, a URI prefix has
 *   no scheme or no trailing slash, or there are more rules of one kind than [PeerPolicy.HARD_MAXIMUM_RULES].
 * @since 1.0.0
 */
public fun peerPolicy(configure: PeerPolicyBuilder.() -> Unit): PeerPolicy {
    val builder = PeerPolicyBuilder()
    builder.configure()
    return builder.build()
}
