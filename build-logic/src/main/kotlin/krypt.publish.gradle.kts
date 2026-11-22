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
    id("krypt.base")
}

val kryptUrl = "https://github.com/davils-com/krypt"

kreate {
    project {
        publish {
            enabled = true
            inceptionYear = 2026
            website = kryptUrl

            pom {
                issueManagement {
                    system = "GitHub Issues"
                    url = "$kryptUrl/issues"
                }

                ciManagement {
                    system = "GitHub Actions"
                    url = "$kryptUrl/actions"
                }

                licenses {
                    license {
                        name = "The Apache License, Version 2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                        distribution = "repo"
                    }
                }

                developers {
                    developer {
                        id = "davils"
                        name = "Davils"
                        email = "development@davils.com"
                        organization = "Davils"
                        timezone = "Europe/Berlin"
                    }
                }

                scm {
                    url = kryptUrl
                    connection = "scm:git:$kryptUrl.git"
                    developerConnection = "scm:git:ssh://git@github.com/davils-com/krypt.git"
                }
            }

            releaseGuard {
                enabled = true
                releaseBranch = "main"
                tagPrefix = ""
            }

            repositories {
                maven {
                    enabled = true
                    name = "Davils"
                    releases = "https://repo.davils.com/releases"
                    snapshots = "https://repo.davils.com/snapshots"
                    usernameEnv = "DAVILS_MAVEN_NAME"
                    passwordEnv = "DAVILS_MAVEN_SECRET"
                    signPublications = true
                    allowInsecureProtocol = false
                }
            }
        }
    }
}
