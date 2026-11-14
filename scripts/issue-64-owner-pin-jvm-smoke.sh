#!/usr/bin/env bash
set -euo pipefail
# JVM-only test without Gradle/Android SDK. All downloaded jars live in /tmp.
root="$(cd "$(dirname "$0")/.." && pwd)"
cache="/tmp/rootark-kotlin-issue64-w1"
mkdir -p "$cache"
java17=""
if [ -x "$cache/jdk17/bin/java" ]; then
  java17="$cache/jdk17/bin/java"
elif [ -n "$(printenv JAVA17_HOME || true)" ] && [ -x "$(printenv JAVA17_HOME)/bin/java" ]; then
  java17="$(printenv JAVA17_HOME)/bin/java"
else
  curl -fsSL --connect-timeout 15 --max-time 180 \
    "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse" \
    -o "$cache/jdk17.tar.gz"
  mkdir -p "$cache/jdk17"
  tar -xzf "$cache/jdk17.tar.gz" -C "$cache/jdk17" --strip-components=1
  java17="$cache/jdk17/bin/java"
fi
download() {
  local relative="$1" target="$2"
  if [ ! -s "$cache/$target" ]; then
    curl -fsSL "https://repo.maven.apache.org/maven2/$relative" -o "$cache/$target"
  fi
}
download "org/jetbrains/kotlin/kotlin-compiler-embeddable/2.0.21/kotlin-compiler-embeddable-2.0.21.jar" compiler.jar
download "org/jetbrains/kotlin/kotlin-stdlib/2.0.21/kotlin-stdlib-2.0.21.jar" stdlib.jar
download "org/jetbrains/kotlin/kotlin-script-runtime/2.0.21/kotlin-script-runtime-2.0.21.jar" script.jar
download "org/jetbrains/kotlin/kotlin-reflect/2.0.21/kotlin-reflect-2.0.21.jar" reflect.jar
download "org/jetbrains/intellij/deps/trove4j/1.0.20200330/trove4j-1.0.20200330.jar" trove.jar
download "org/jetbrains/annotations/13.0/annotations-13.0.jar" annotations.jar
download "org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.6.4/kotlinx-coroutines-core-jvm-1.6.4.jar" coroutines.jar
download "org/json/json/20240303/json-20240303.jar" json.jar
download "org/junit/platform/junit-platform-console-standalone/1.11.0/junit-platform-console-standalone-1.11.0.jar" junit.jar
download "junit/junit/4.13.2/junit-4.13.2.jar" junit4.jar
download "org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar" hamcrest.jar
compiler_cp="$cache/compiler.jar:$cache/stdlib.jar:$cache/script.jar:$cache/reflect.jar:$cache/trove.jar:$cache/annotations.jar:$cache/coroutines.jar"
runtime_cp="$cache/stdlib.jar:$cache/json.jar:$cache/junit.jar:$cache/junit4.jar:$cache/hamcrest.jar"
out="$cache/classes"
mkdir -p "$out"
"$java17" -cp "$compiler_cp" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
  -no-stdlib -no-reflect -jvm-target 17 \
  -classpath "$runtime_cp" -d "$out" \
  "$root/android/core/src/main/kotlin/dev/rootark/core/paths/PortablePathValidator.kt" \
  "$root/android/core/src/main/kotlin/dev/rootark/core/sync/SyncModels.kt" \
  "$root/android/core/src/main/kotlin/dev/rootark/core/sync/ProtectedSyncContent.kt" \
  "$root/android/core/src/main/kotlin/dev/rootark/core/sync/OwnerPinnedOfflineAdmission.kt" \
  "$root/android/core/src/test/kotlin/dev/rootark/core/sync/OwnerPinnedOfflineAdmissionTest.kt" \
  "$root/android/app/src/main/java/dev/rootark/android/StrictRfc8259Json.kt" \
  "$root/android/app/src/main/java/dev/rootark/android/OwnerPinnedOfflineImport.kt" \
  "$root/android/app/src/test/java/dev/rootark/android/OwnerPinnedOfflineImportTest.kt"
"$java17" -cp "$out:$runtime_cp:$root/android/core/src/test/resources" \
  org.junit.platform.console.ConsoleLauncher execute \
  --disable-banner --select-class dev.rootark.core.sync.OwnerPinnedOfflineAdmissionTest \
  --select-class dev.rootark.android.OwnerPinnedOfflineImportTest
