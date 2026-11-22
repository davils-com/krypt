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

/**
 * COSE of krypt: deterministic CBOR, COSE messages, COSE keys and CBOR Web Tokens.
 */
@SuppressWarnings("module")
module com.davils.krypt.cose {
    requires transitive kotlin.stdlib;
    requires transitive com.davils.krypt.x509;

    exports com.davils.krypt.cose;
    exports com.davils.krypt.cose.cbor;
    exports com.davils.krypt.cose.cwt;
    exports com.davils.krypt.cose.key;
}
