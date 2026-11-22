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

package com.davils.krypt.jose.fixture

internal object Vectors {
    const val RFC7517_KEY_SET: String =
        """{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"""" +
            """4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"},{"kty":"RSA","n":"0vx7""" +
            "agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPeb" +
            "WKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY" +
            "368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu" +
            """0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS""" +
            """256","kid":"2011-04-29"}]}"""

    const val RFC7517_X5C_KEY: String =
        """{"kty":"RSA","use":"sig","kid":"1b94c","n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz""" +
            "2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84T" +
            "y5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1" +
            "wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2" +
            """C32qvbWbjZ_jBPD5eunqsIo1vQ","e":"AQAB","x5c":["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQE""" +
            "BBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZ" +
            "W50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTV" +
            "aMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50a" +
            "XR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL6" +
            "4zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1Nbgizc" +
            "AblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXP" +
            "Lfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRD" +
            "Wm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0" +
            "BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J" +
            "1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2" +
            "Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1i" +
            """J684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]}"""

    const val RFC7517_ENCRYPTED_KEY: String =
        "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiIyV0NUY0paMVJ2ZF9DSnVKcmlwUTF3IiwicDJjIjo0MD" +
            "k2LCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiandrK2pzb24ifQ.TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-" +
            "TR1uIxR9p6hsRQh9Tk7BA.Ye9j1qs22DmRSAddIh-VnA.AwhB8lxrlKjFn02LGWEqg27H4Tg9fyZAbFv3p5ZicHpj6" +
            "4QyHC44qqlZ3JEmnZTgQowIqZJ13jbyHB8LgePiqUJ1hf6M2HPLgzw8L-mEeQ0jvDUTrE07NtOerBk8bwBQyZ6g0kQ" +
            "3DEOIglfYxV8-FJvNBYwbqN1Bck6d_i7OtjSHV-8DIrp-3JcRIe05YKy3Oi34Z_GOiAc1EK21B11c_AE11PII_wvvt" +
            "RiUiG8YofQXakWd1_O98Kap-UgmyWPfreUJ3lJPnbD4Ve95owEfMGLOPflo2MnjaTDCwQokoJ_xplQ2vNPz8iguLcH" +
            "BoKllyQFJL2mOWBwqhBo9Oj-O800as5mmLsvQMTflIrIEbbTMzHMBZ8EFW9fWwwFu0DWQJGkMNhmBZQ-3lvqTc-M6-" +
            "gWA6D8PDhONfP2Oib2HGizwG1iEaX8GRyUpfLuljCLIe1DkGOewhKuKkZh04DKNM5Nbugf2atmU9OP0Ldx5peCUtRG" +
            "1gMVl7Qup5ZXHTjgPDr5b2N731UooCGAUqHdgGhg0JVJ_ObCTdjsH4CF1SJsdUhrXvYx3HJh2Xd7CwJRzU_3Y1GxYU" +
            "6-s3GFPbirfqqEipJDBTHpcoCmyrwYjYHFgnlqBZRotRrS95g8F95bRXqsaDY7UgQGwBQBwy665d0zpvTasvfXf_c0" +
            "MWAl-neFaKOW_Px6g4EUDjG1GWSXV9cLStLw_0ovdApDIFLHYHePyagyHjouQUuGiq7BsYwYrwaF06tgB8hV8omLNf" +
            "MEmDPJaZUzMuHw6tBDwGkzD-tS_ub9hxrpJ4UsOWnt5rGUyoN2N_c1-TQlXxm5oto14MxnoAyBQBpwIEgSH3Y4ZhwK" +
            "BhHPjSo0cdwuNdYbGPpb-YUvF-2NZzODiQ1OvWQBRHSbPWYz_xbGkgD504LRtqRwCO7CC_CyyURi1sEssPVsMJRX_U" +
            "4LFEOc82TiDdqjKOjRUfKK5rqLi8nBE9soQ0DSaOoFQZiGrBrqxDsNYiAYAmxxkos-i3nX4qtByVx85sCE5U_0MqG7" +
            "COxZWMOPEFrDaepUV-cOyrvoUIng8i8ljKBKxETY2BgPegKBYCxsAUcAkKamSCC9AiBxA0UOHyhTqtlvMksO7AEhNC" +
            "2-YzPyx1FkhMoS4LLe6E_pFsMlmjA6P1NSge9C5G5tETYXGAn6b1xZbHtmwrPScro9LWhVmAaA7_bxYObnFUxgWtK4" +
            "vzzQBjZJ36UTk4OTB-JvKWgfVWCFsaw5WCHj6Oo4jpO7d2yN7WMfAj2hTEabz9wumQ0TMhBduZ-QON3pYObSy7TSC1" +
            "vVme0NJrwF_cJRehKTFmdlXGVldPxZCplr7ZQqRQhF8JP-l4mEQVnCaWGn9ONHlemczGOS-A-wwtnmwjIB1V_vgJRf" +
            "4FdpV-4hUk4-QLpu3-1lWFxrtZKcggq3tWTduRo5_QebQbUUT_VSCgsFcOmyWKoj56lbxthN19hq1XGWbLGfrrR6MW" +
            "h23vk01zn8FVwi7uFwEnRYSafsnWLa1Z5TpBj9GvAdl2H9NHwzpB5NqHpZNkQ3NMDj13Fn8fzO0JB83Etbm_tnFQfc" +
            "b13X3bJ15Cz-Ww1MGhvIpGGnMBT_ADp9xSIyAM9dQ1yeVXk-AIgWBUlN5uyWSGyCxp0cJwx7HxM38z0UIeBu-MytL-" +
            "eqndM7LxytsVzCbjOTSVRmhYEMIzUAnS1gs7uMQAGRdgRIElTJESGMjb_4bZq9s6Ve1LKkSi0_QDsrABaLe55UY0zF" +
            "4ZSfOV5PMyPtocwV_dcNPlxLgNAD1BFX_Z9kAdMZQW6fAmsfFle0zAoMe4l9pMESH0JB4sJGdCKtQXj1cXNydDYozF" +
            "7l8H00BV_Er7zd6VtIw0MxwkFCTatsv_R-GsBCH218RgVPsfYhwVuT8R4HarpzsDBufC4r8_c8fc9Z278sQ081jFjO" +
            "ja6L2x0N_ImzFNXU6xwO-Ska-QeuvYZ3X_L31ZOX4Llp-7QSfgDoHnOxFv1Xws-D5mDHD3zxOup2b2TppdKTZb9eW2" +
            "vxUVviM8OI9atBfPKMGAOv9omA-6vv5IxUH0-lWMiHLQ_g8vnswp-Jav0c4t6URVUzujNOoNd_CBGGVnHiJTCHl88L" +
            "QxsqLHHIu4Fz-U2SGnlxGTj0-ihit2ELGRv4vO8E1BosTmf0cx3qgG0Pq0eOLBDIHsrdZ_CCAiTc0HVkMbyq1M6qEh" +
            "M-q5P6y1QCIrwg.0HFmhOzsQ98nNWJjIHkR7A"

    const val RFC7515_HMAC_KEY: String =
        """{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUu""" +
            """TwjAzZr1Z9CAow"}"""

    const val RFC7515_EC_KEY: String =
        """{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m""" +
            """36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"""

    const val RFC7515_HMAC_JWS: String =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6" +
            "Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    const val RFC7515_EC_JWS: String =
        "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9p" +
            "c19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-K" +
            "g6NU1Q"

    const val RFC7515_CRITICAL_JWS: String =
        "eyJhbGciOiJub25lIiwNCiAiY3JpdCI6WyJodHRwOi8vZXhhbXBsZS5jb20vVU5ERUZJTkVEIl0sDQogImh0dHA6Ly9leGFt" +
            "cGxlLmNvbS9VTkRFRklORUQiOnRydWUNCn0.RkFJTA."

    const val RFC7797_JWS: String =
        "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"

    const val RFC7797_PAYLOAD: String = "$.02"

    const val RFC7516_KEY: String = """{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"""

    const val RFC7516_CEK: String = "04d31fc5549dfcfe0b649dfa3faa6ace6b7cd42d6f6b09dbc8b100f08f9c2ccf"

    const val RFC7516_IV: String = "AxY8DCtDaGlsbGljb3RoZQ"

    const val RFC7516_JWE: String =
        "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2Il" +
            "rT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ"

    const val RFC7516_PLAINTEXT: String = "Live long and prosper."

    const val RFC7517_PASSWORD: String = "Thus from my lips, by yours, my sin is purged."

    const val RFC7638_THUMBPRINT: String = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

    const val RFC8037_PRIVATE: String =
        """{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",""" +
            """"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"""

    const val RFC8037_THUMBPRINT: String = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

    const val RFC8037_JWS: String =
        "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6d" +
            "WbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

    const val RFC8037_PAYLOAD: String = "Example of Ed25519 signing"

    const val RFC8037_X25519_PRIVATE: String =
        """{"kty":"OKP","crv":"X25519","kid":"Bob","d":"XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os",""" +
            """"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"""

    const val RFC8037_X25519_EPHEMERAL: String =
        """{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}"""

    const val RFC8037_X25519_SHARED: String = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    const val RFC7518_ALICE: String =
        """{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",""" +
            """"y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps","d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}"""

    const val RFC7518_BOB: String =
        """{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",""" +
            """"y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"""

    const val RFC7518_SHARED: String = "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4"

    const val RFC7518_DERIVED: String = "VqqN6vgjbSBcIijNcacQGg"
}
