#!/usr/bin/env bash
set -euo pipefail

echo "Generating placeholder SLSA provenance..."

OUTPUT_DIR="artifacts/provenance"
mkdir -p "${OUTPUT_DIR}"

cat > "${OUTPUT_DIR}/provenance.json" <<'EOF'
{
  "type": "slsa-provenance-0.2",
  "subject": [
    {
      "name": "gateway",
      "digest": {
        "sha256": "TODO"
      }
    }
  ],
  "builder": {
    "id": "https://github.com/example/qsafe/.github/workflows/ci.yaml"
  },
  "buildType": "https://slsa.dev/spec/v0.2/workflow/spec",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/example/qsafe",
      "digest": {
        "sha1": "TODO"
      }
    }
  }
}
EOF

echo "Provenance placeholder written to ${OUTPUT_DIR}/provenance.json"
