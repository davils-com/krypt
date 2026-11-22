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

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("krypt.base")
    id("krypt.dependency-locking")
    id("krypt.git-hooks")
    id("krypt.trivy")
    id("krypt.assurance")
    id("krypt.platform")
    id("krypt.detekt")
    id("krypt.tool-classpaths")
}

val catalog: VersionCatalog = the<VersionCatalogsExtension>().named("libs")
val benchmarkRuntimeVersion: String = catalog.findVersion("kotlinx-benchmark").get().requiredVersion
val jmhCoreVersion: String = catalog.findVersion("jmh").get().requiredVersion

kreate {
    assurance {
        advisories {
            configurations = setOf(
                "compileClasspath",
                "runtimeClasspath",
                "benchmarksCompileClasspath",
                "benchmarksRuntimeClasspath",
            )
        }
    }

    project {
        benchmark {
            enabled = true
            runtimeVersion = benchmarkRuntimeVersion
            jmhVersion = jmhCoreVersion

            profiles {
                named("main") {
                    warmups = 5
                    iterations = 10
                    iterationTime = 1
                    iterationTimeUnit = "s"
                    mode = "thrpt"
                    outputTimeUnit = "s"
                    advanced("jvmForks", "2")
                }

                register("smoke") {
                    warmups = 1
                    iterations = 3
                    iterationTime = 500
                    iterationTimeUnit = "ms"
                    mode = "thrpt"
                    outputTimeUnit = "s"
                    advanced("jvmForks", "1")
                }
            }

            regression {
                enabled = true
                profile = "main"
                maxRegressionPercent = 10.0
                requireSignificance = true
                failOnMissingBenchmark = true
            }
        }
    }
}
