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

package com.davils.krypt.acme.fixture

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

internal object Vectors {
    const val RFC8555_TOKEN: String = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"

    const val RFC8037_PUBLIC: String =
        """{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"""

    const val RFC8037_THUMBPRINT: String = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

    const val KEY_AUTHORIZATION: String = "$RFC8555_TOKEN.$RFC8037_THUMBPRINT"

    const val DNS01_VALUE: String = "lAV291d372xyXVEZRY9j2FQ8g1TYpOaJr620CiahePA"

    const val ACME_IDENTIFIER_VALUE: String = "0420940576f75777ef6c725d5119458f63d8543c8354d8a4e689afadb40a26a178f0"

    const val RFC9773_KEY_IDENTIFIER: String = "69885b6b87464041e1b37b847ba0ae2cde01c8d4"

    const val RFC9773_SERIAL: String = "0087654321"

    const val RFC9773_IDENTIFIER: String = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"

    fun hex(text: String): ByteString = checkNotNull(Hex.decode(text).getOrNull())
}
