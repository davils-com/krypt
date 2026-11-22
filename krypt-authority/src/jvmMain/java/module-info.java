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
 * The certificate authority of krypt: issuance, profiles, policy, revocation and status.
 */
module com.davils.krypt.authority {
    requires transitive kotlin.stdlib;
    requires transitive com.davils.krypt.ocsp;
    requires transitive com.davils.krypt.keystore;

    exports com.davils.krypt.authority;
    exports com.davils.krypt.authority.policy;
    exports com.davils.krypt.authority.profile;
    exports com.davils.krypt.authority.store;
}
