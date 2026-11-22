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

package com.davils.krypt.authority.fixture

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.authority.CertificateAuthority
import com.davils.krypt.authority.IssuanceRequest
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.Environment
import com.davils.krypt.core.EnvironmentBuilder
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

internal const val HOST: String = "api.example.com"
internal const val ROOT_DAYS: Int = 3_650

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal fun testEnvironment(
    clock: Clock = MovableClock(),
    configure: EnvironmentBuilder.() -> Unit = {},
): Environment = environment {
    this.clock = clock
    configure()
}

internal val crypto: Crypto = Crypto(testEnvironment())

internal suspend fun rootAuthority(
    on: Crypto = crypto,
    policy: IssuancePolicy = IssuancePolicy.Default,
    pathLength: Int? = null,
    repository: MemoryRepository = MemoryRepository(),
): TestAuthority {
    val pair = on.keys.generate(KeyType.P256)
    val signer = on.signatures.signer(pair.privateKey)
    val certificate = CertificateAuthority.createRoot(
        crypto = on,
        signer = signer,
        subject = distinguishedName { commonName("Root") },
        validity = ROOT_DAYS.days,
        pathLength = pathLength,
    )
    val authority = CertificateAuthority(
        crypto = on,
        certificate = certificate,
        signer = signer,
        repository = repository,
        policy = policy,
    )
    return TestAuthority(authority = authority, pair = pair, repository = repository)
}

internal suspend fun serverRequest(
    name: GeneralName = GeneralName.Dns(HOST),
    type: KeyType = KeyType.P256,
    profile: CertificateProfile = CertificateProfile.TlsServer,
): IssuanceRequest {
    val pair = crypto.keys.generate(type)
    return IssuanceRequest(
        subject = distinguishedName { commonName(HOST) },
        publicKey = pair.publicKey,
        profile = profile,
        names = listOf(name),
    )
}

internal suspend fun CertificateAuthority.issued(request: IssuanceRequest): Certificate =
    checkNotNull(issue(request).getOrNull())
