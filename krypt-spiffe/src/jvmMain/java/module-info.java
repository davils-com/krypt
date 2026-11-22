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
 * SPIFFE of krypt: SPIFFE ids, SVIDs, trust bundles and their sources.
 */
@SuppressWarnings("module")
module com.davils.krypt.spiffe {
    requires transitive kotlin.stdlib;
    requires transitive com.davils.krypt.jose;

    exports com.davils.krypt.spiffe;
    exports com.davils.krypt.spiffe.bundle;
    exports com.davils.krypt.spiffe.jwt;
    exports com.davils.krypt.spiffe.source;
    exports com.davils.krypt.spiffe.x509;
}
