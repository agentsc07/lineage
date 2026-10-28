# Prior art and what Lineage adds

Written from general knowledge of these products, not from a hands-on comparison; check their current documentation before quoting this.

| | What it does well | What Lineage adds |
|---|---|---|
| **Trivy** (and similar scanners) | Known vulnerabilities, misconfigurations and secrets in images, filesystems and package manifests | Lineage reuses OSV for known CVEs and advisories. It adds checks for things a CVE database does not contain: behaviour of package code against its stated purpose, model weights against a base, chat templates and tokenizers, dataset poisoning, MCP tool descriptions and responses |
| **JFrog Artifactory / Xray / Curation** | A proxy that every build pulls through; policy on licences, vulnerabilities and known-malicious packages; compliant-version selection | Lineage uses the same proxy pattern for packages (PEP 503 index serving only admitted wheels) and the same compliant-version idea. It adds lineage across data, model, fine-tune and package (ghost nodes included), fine-tune-versus-base comparison, MCP pinning and response scanning, federated-update gating, and use-time attestation that fails closed |
| **Sigstore / in-toto / SLSA** | Signing and provenance statements for build artifacts | Lineage's passports are in-toto statements, but trust is decided by the verifier from a policy-pinned publisher list with a scope, never by the signer, and a signature alone never clears a check |
| **Model-hub scanners (pickle scanners)** | Flag dangerous pickle opcodes | Lineage refuses pickle by policy and goes on to templates, tokenizers, custom code, weights and cards |

Not claimed: runtime prompt or output filtering, and any guarantee against a weight-only backdoor with no known base.
