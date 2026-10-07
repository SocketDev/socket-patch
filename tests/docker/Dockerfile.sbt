# sbt / Mill / scala-cli test image: base + three JDKs + the sbt launcher,
# Mill and scala-cli, every download sha256-pinned
# (docs/design/sbt-support.md; `docker_e2e_sbt.rs`, feature `docker-e2e`).
#
# The JDKs are copied out of digest-pinned eclipse-temurin images: 8 for
# sbt <= 1.3.13, 17 for later sbt and every Mill / scala-cli cell, 21 for
# the JDK-21 legs. The sbt launcher fetches whatever
# `project/build.properties` pins, so one launcher serves every sbt version
# in SOCKET_PATCH_SBT_DOCKER_VERSIONS.
#
# Run with `docker run --rm -m 2g` and `--test-threads=1`.
#
# Warm caches are baked at build time (last layer): each sbt version in
# SBT_WARM_VERSIONS boots once and resolves the agent fixture's
# dependencies except the patched GAV (commons-text 1.9, which every agent
# cell downloads itself), into the image's ~/.sbt, ~/.ivy2 and
# ~/.cache/coursier; Mill 1.x and scala-cli boot once too.
FROM eclipse-temurin@sha256:9ade16dc859a6db5b79f17912643529d366e8baa01eaab8881d7444fcafec05c AS jdk8
FROM eclipse-temurin@sha256:5d6042fb8cdc14d614e4e421f52e3211fc5aeadddce44cbf9de8ed37c791f824 AS jdk17
FROM eclipse-temurin@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b AS jdk21

FROM socket-patch-test-base:latest

# eclipse-temurin:8-jdk, :17-jdk and :21-jdk (multi-arch index digests,
# 2026-10-02).
COPY --from=jdk8 /opt/java/openjdk /opt/jdk8
COPY --from=jdk17 /opt/java/openjdk /opt/jdk17
COPY --from=jdk21 /opt/java/openjdk /opt/jdk21
ENV JAVA_HOME=/opt/jdk17
ENV PATH=/opt/jdk17/bin:$PATH

ARG SBT_LAUNCHER_VERSION=1.13.0
ARG SBT_LAUNCHER_SHA256=06806805ffd26232727326216766ed4793b549f8c1e6ffeef2e610db7245b698
ARG MILL_011_VERSION=0.11.13
ARG MILL_011_SHA256=7d21c1e14cad4109a9edd980a2fbd1e386032a1b3b78db1627d68752dafa3c70
ARG MILL_012_VERSION=0.12.17
ARG MILL_012_SHA256=7126698a51526c29aa53c53fb5e0d5b64c979108127e84b33cc9e9dde9e43be0
ARG MILL_1_VERSION=1.1.10
ARG MILL_1_SHA256=63538d1cb27c29dd36821d832a964580e3bf046d956f6e6b3cd55d1f0124a561
ARG SCALA_CLI_VERSION=1.17.1
ARG SCALA_CLI_SHA256_AMD64=4186bfac6552097fbfd3939bdf2ecdec1cb55baafcbf6259bef5c04e08858eb3
ARG SCALA_CLI_SHA256_ARM64=a12ed53f4723f3e9312a2383e47664b4beaccf2be366cff40adf6b054426156f

RUN set -eu \
 && cd /tmp \
 && curl -fsSL --retry 3 -o sbt.tgz \
      "https://github.com/sbt/sbt/releases/download/v${SBT_LAUNCHER_VERSION}/sbt-${SBT_LAUNCHER_VERSION}.tgz" \
 && echo "${SBT_LAUNCHER_SHA256}  sbt.tgz" | sha256sum -c - \
 && tar -C /opt -xzf sbt.tgz \
 && ln -s /opt/sbt/bin/sbt /usr/local/bin/sbt \
 && rm -f sbt.tgz

# One launcher script per Mill line, installed as mill-<version>.
RUN set -eu \
 && cd /tmp \
 && curl -fsSL --retry 3 -o mill-011 \
      "https://github.com/com-lihaoyi/mill/releases/download/${MILL_011_VERSION}/${MILL_011_VERSION}" \
 && echo "${MILL_011_SHA256}  mill-011" | sha256sum -c - \
 && install -m 0755 mill-011 "/usr/local/bin/mill-${MILL_011_VERSION}" \
 && curl -fsSL --retry 3 -o mill-012 \
      "https://repo1.maven.org/maven2/com/lihaoyi/mill-dist/${MILL_012_VERSION}/mill-dist-${MILL_012_VERSION}-mill.sh" \
 && echo "${MILL_012_SHA256}  mill-012" | sha256sum -c - \
 && install -m 0755 mill-012 "/usr/local/bin/mill-${MILL_012_VERSION}" \
 && curl -fsSL --retry 3 -o mill-1 \
      "https://repo1.maven.org/maven2/com/lihaoyi/mill-dist/${MILL_1_VERSION}/mill-dist-${MILL_1_VERSION}-mill.sh" \
 && echo "${MILL_1_SHA256}  mill-1" | sha256sum -c - \
 && install -m 0755 mill-1 "/usr/local/bin/mill-${MILL_1_VERSION}" \
 && rm -f mill-011 mill-012 mill-1

RUN set -eu \
 && cd /tmp \
 && case "$(dpkg --print-architecture)" in \
      amd64) arch=x86_64; sum="${SCALA_CLI_SHA256_AMD64}";; \
      arm64) arch=aarch64; sum="${SCALA_CLI_SHA256_ARM64}";; \
      *) echo "unsupported architecture" >&2; exit 1;; \
    esac \
 && curl -fsSL --retry 3 -o scala-cli.gz \
      "https://github.com/VirtusLab/scala-cli/releases/download/v${SCALA_CLI_VERSION}/scala-cli-${arch}-pc-linux.gz" \
 && echo "${sum}  scala-cli.gz" | sha256sum -c - \
 && gunzip scala-cli.gz \
 && install -m 0755 scala-cli /usr/local/bin/scala-cli \
 && rm -f scala-cli \
 && /opt/jdk8/bin/java -version \
 && /opt/jdk21/bin/java -version \
 && java -version \
 && scala-cli version --cli-version | grep -Fx "${SCALA_CLI_VERSION}"

# Warm caches (see the header). sbt <= 1.3.13 runs on JDK 8; sbt 2 in
# server mode. The fixture build is the agent cells' one minus the patched
# GAV: commons-lang3 3.11 is commons-text 1.9's only dependency.
# 0.13.18 too: an unwarmed Ivy line resolves its whole build definition
# from the network, serially, into each test's private Ivy home (its hosted
# group took ~1380 s that way, ~420 s warm). The Coursier lines (1.3.13,
# 1.9.9) boot quickly cold and stay out: the scala-cli real-tool test serves
# the image's Central cache from memory, which more lines would bloat past
# its 2g container.
ARG SBT_WARM_VERSIONS="0.13.18 1.2.8 1.13.0 2.0.9"
RUN set -eu \
 && for v in ${SBT_WARM_VERSIONS}; do \
      d="/tmp/warm-$v"; mkdir -p "$d/project"; \
      echo "sbt.version=$v" > "$d/project/build.properties"; \
      printf '%s\n' 'autoScalaLibrary := false' 'crossPaths := false' \
        'libraryDependencies += "org.apache.commons" % "commons-lang3" % "3.11"' > "$d/build.sbt"; \
      case "$v" in 0.*|1.[0-3].*) jdk=/opt/jdk8;; *) jdk=/opt/jdk17;; esac; \
      case "$v" in 2.*) extra=--server;; *) extra=;; esac; \
      (cd "$d" && JAVA_HOME="$jdk" PATH="$jdk/bin:$PATH" \
        sbt -batch -no-colors -Dsbt.server.autostart=false $extra update); \
      rm -rf "$d"; \
    done \
 && d=/tmp/warm-mill && mkdir -p "$d/foo/src" && cd "$d" \
 && printf '%s\n' '//| mill-version: '"${MILL_1_VERSION}" 'package build' 'import mill.*, scalalib.*' \
      'object foo extends ScalaModule {' '  def scalaVersion = "2.13.16"' \
      '  def mvnDeps = Seq(mvn"org.apache.commons:commons-lang3:3.11")' '}' > build.mill \
 && "mill-${MILL_1_VERSION}" --no-daemon --ticker false show foo.compileClasspath > /dev/null \
 && cd / && rm -rf "$d" \
 && d=/tmp/warm-scala-cli && mkdir -p "$d" && cd "$d" \
 && printf '%s\n' '//> using scala 3.3.6' '//> using dep org.apache.commons:commons-lang3:3.11' > project.scala \
 && echo '@main def m() = println("warm")' > Main.scala \
 && scala-cli compile . --server=false > /dev/null \
 && cd / && rm -rf "$d"
