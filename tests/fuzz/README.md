# Fuzzing Harness

## Scope
- Handshake frame parsing (`proto/api/v1`) via protobuf harness.
- Session state transitions (replay vault, rotation scheduler).
- AEAD envelope framing and metadata deserialization.
- Attestation bundle validators and policy evaluators.

## Toolchain
- Rust-based libFuzzer and honggfuzz targets orchestrated by Bazel.
- go-fuzz / oss-fuzz adapters for Go-based components.
- Sanitizers (asan/ubsan/msan) enabled via Bazel transitions and devcontainer toolchains.

## Usage
```
bazel run //tests/fuzz:handshake_proto -- --max_total_time=60
```
Corpus artifacts stored under `tests/fuzz/corpus` and synchronized via artifact registry.
