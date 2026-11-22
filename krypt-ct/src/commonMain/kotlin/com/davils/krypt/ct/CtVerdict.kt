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

package com.davils.krypt.ct

import com.davils.krypt.ct.internal.VerdictParts

/**
 * Whether a certificate complies with a [CtPolicy], and why.
 *
 * @property compliance the verdict.
 * @property results the verification of every timestamp found.
 * @property required how many valid timestamps of distinct logs the policy asks for this certificate.
 * @property logs how many distinct logs gave a valid timestamp.
 * @property operators how many distinct operators run those logs.
 * @since 1.0.0
 */
public class CtVerdict private constructor(
    public val compliance: CtCompliance,
    public val results: List<SctResult>,
    public val required: Int,
    public val logs: Int,
    public val operators: Int,
) {
    /**
     * Whether the certificate complies.
     *
     * @since 1.0.0
     */
    public val isCompliant: Boolean get() = compliance == CtCompliance.Compliant

    internal constructor(parts: VerdictParts) : this(
        compliance = parts.compliance,
        results = parts.results,
        required = parts.required,
        logs = parts.logs,
        operators = parts.operators,
    )

    /**
     * Shows the verdict and the counts.
     *
     * @return the verdict as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CtVerdict($compliance, logs=$logs/$required, operators=$operators)"
}
