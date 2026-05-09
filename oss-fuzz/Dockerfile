# OSS-Fuzz build image for Varta.
#
# Mirrors `projects/varta/Dockerfile` in the upstream OSS-Fuzz repo
# once the project is registered.  See `oss-fuzz/project.yaml` for the
# overall manifest.

FROM gcr.io/oss-fuzz-base/base-builder-rust

# OSS-Fuzz convention: clone the project into `$SRC/<project-name>`
# during image build so the corpus and source tree are available to
# `build.sh`.  We do a shallow clone to keep image build times low —
# OSS-Fuzz infra always re-fetches HEAD before each build anyway.
RUN git clone --depth 1 https://github.com/aramirez087/Varta varta

# `WORKDIR` and `COPY` exactly match the OSS-Fuzz convention.
WORKDIR $SRC/varta
COPY build.sh $SRC/
