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

package com.davils.krypt.primitive.fixture

internal object RfcKeys {
    const val ED25519_PKCS8_PREFIX: String = "302e020100300506032b657004220420"
    const val ED25519_SPKI_PREFIX: String = "302a300506032b6570032100"
    const val X25519_PKCS8_PREFIX: String = "302e020100300506032b656e04220420"
    const val X25519_SPKI_PREFIX: String = "302a300506032b656e032100"

    const val ED25519_SECRET: String = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    const val ED25519_PUBLIC: String = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    const val ED25519_SIGNATURE: String =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970" +
            "1cf9b46bd25bf5f0595bbe24655141438e7a100b"

    const val X25519_ALICE_SECRET: String = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    const val X25519_ALICE_PUBLIC: String = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    const val X25519_BOB_SECRET: String = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    const val X25519_BOB_PUBLIC: String = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    const val X25519_SHARED: String = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    const val HPKE_INFO: String = "4f6465206f6e2061204772656369616e2055726e"
    const val HPKE_EPHEMERAL_SECRET: String = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
    const val HPKE_EPHEMERAL_PUBLIC: String = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
    const val HPKE_RECIPIENT_SECRET: String = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
    const val HPKE_RECIPIENT_PUBLIC: String = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
    const val HPKE_PLAINTEXT: String = "4265617574792069732074727574682c20747275746820626561757479"
    const val HPKE_AAD: String = "436f756e742d30"
    const val HPKE_CIPHERTEXT: String = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9" +
        "6d8770ac83d07bea87e13c512a"
    const val HPKE_EXPORTED: String = "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
}
