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

import com.davils.kreate.platform.WebEnvironment
import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    id("krypt.base")
}

val kryptModuleName: String = "com.davils.krypt.${name.removePrefix("krypt-").replace("-", "")}"

kreate {
    platform {
        javaVersion = JavaVersion.VERSION_25
        explicitApi = true
        allWarningsAsErrors = true

        compiler {
            progressiveMode = true
            extraWarnings = true
            languageVersion = KotlinVersion.KOTLIN_2_4
            apiVersion = KotlinVersion.KOTLIN_2_4
            jvmDefault = JvmDefaultMode.NO_COMPATIBILITY
        }

        jvm {
            moduleName = kryptModuleName
            javaWarningsAsErrors = true
        }
    }
}

pluginManager.withPlugin("org.jetbrains.kotlin.multiplatform") {
    kreate {
        platform {
            multiplatform {
                targets {
                    jvm = true
                    wasmJs = setOf(WebEnvironment.NODE)
                }
            }
        }
    }
}
