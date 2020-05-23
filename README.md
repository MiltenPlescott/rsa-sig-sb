# RSA silver-box signature scheme using secure silver module

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

TL;DR: run [START.bat](https://github.com/MiltenPlescott/rsa-sig-sb/blob/master/START.bat) and follow the on-screen instruction

#### Project structure
```
  Root project 'rsa-sig-sb'
   ├── Subroject ':security-providers'
   ├── Subroject ':benchmark'
   ├── Subroject ':ssm-link'
   ├── Subroject ':secure-silver-module'
   └── Subroject ':central-processing-unit'
```

-------------------------------------------

- you need to have installed JDK-11 installed, for example: [AdoptOpenJDK 11 (LTS)](https://adoptopenjdk.net/releases.html?variant=openjdk11&jvmVariant=hotspot)

- you don't need to have [Gradle](https://gradle.org/) installed, running gradlew script for the first time will download appropriate Gradle version (6.3)

- [SSM](secure-silver-module) needs to be running in one console window, then you can run benchmark in another console window

- building [rsa-sig-sb](https://github.com/MiltenPlescott/rsa-sig-sb) for the first time will download all necessary dependencies

- use `gradlew.bat` commands on Windows and `./gradlew` on Linux

#### How to build program:
```bat
> gradlew.bat build
```
```sh
$ ./gradlew build
```

#### How to delete build:
```bat
> gradlew.bat clean
```
```sh
$ ./gradlew clean
```

#### How to see available security providers:
```bat
> gradlew.bat :security-providers:run
```
```sh
$ ./gradlew :security-providers:run
```

#### How to start SSM:
```bat
> gradlew.bat :secure-silver-module:run
```
```sh
$ ./gradlew :secure-silver-module:run
```

#### How to start benchmark:
```bat
> gradlew.bat :benchmark:run
```
```sh
$ ./gradlew :benchmark:run
```

-------------------------------------------

#### How to display project tree:
```bat
> gradlew.bat projects
```
```sh
$ ./gradlew projects
```

#### How to display all available tasks:
```bat
> gradlew.bat tasks --all
```
```sh
$ ./gradlew tasks --all
```

#### How to display dependency tree for CPU subproject:
```bat
> gradlew.bat :central-processing-unit:dependencies
```
```sh
$ ./gradlew :central-processing-unit:dependencies
```

#### How to display dependency tree for SSM subproject:
```bat
> gradlew.bat :secure-silver-module:dependencies
```
```sh
$ ./gradlew :secure-silver-module:dependencies
```

-------------------------------------------

#### How to change console output:
- edit `org.gradle.console` in `gradle.properties` file and change `verbose` to: `auto`, `plain` or `rich`

#### How to change key size, hash function output length, maximum number of allowed queries and security provider:
- edit `args = [RSA_BITS, HASH_BITS, MAX_QUERIES, KEY_PAIR_GENERATOR_PROVIDER]` in [secure-silver-module/build.gradle](secure-silver-module/build.gradle)
- run `:security-providers` subprojects for information on supported providers and key sizes

#### How to change benchmark length and security providers:
- edit `args = [BENCHMARK_LENGTH, KEY_PAIR_GENERATOR_PROVIDER, SIGNATURE_PROVIDER]` in [benchmark/build.gradle](benchmark/build.gradle)
- run `:security-providers` subprojects for information on supported providers and key sizes

###### NOTE:
Even if SunMSCAPI is listed as supported on your system, using it will result in getting `InvalidAlgorithmParameterException: Exponent parameter is not supported`, because we are using constant public exponent 65537 and SunMSCAPI doesn't allow choosing public exponent.
See: [/mscapi/RSAKeyPairGenerator.java#L82-L85](https://github.com/AdoptOpenJDK/openjdk-jdk11/blob/master/src/jdk.crypto.mscapi/windows/classes/sun/security/mscapi/RSAKeyPairGenerator.java#L82-L85)

## License

RSA silver-box signature scheme using secure silver module is available under MIT License. See [LICENSE.txt](LICENSE.txt) for more information.

SPDX-License-Identifier: MIT
