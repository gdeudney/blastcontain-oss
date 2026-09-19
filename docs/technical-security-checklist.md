# Technical security checklist

Use this as a bridge from the article series to verifiable technical requirements.
Organizations decide acceptable access, approval authority and exceptions. A check
result is bounded evidence, not certification. Verify runs in the tested runtime;
Drill exercises authorized external attack scenarios; Guard enforces configured
policy where calls pass through its adapters.

| Requirement | Verify today | Guard today | Drill validation / remaining work |
|---|---|---|---|
| Limit runtime privileges and filesystem access | ENV, DISK, PROC and PERSIST probes of the scanner's runtime | No OS sandbox | Cage tests exercise containment; repeat against representative deployments |
| Restrict outbound access | ENV-02/NET-01 probe selected destinations; not exhaustive policy verification | Tool rules; external egress policy helpers only | Exercise authorized exfiltration scenarios; deploy a network boundary |
| Limit secrets and sensitive data access | CRED checks; MEM-01 detection; MEM-05 combines PII with observed egress | Tool-call rules, not protection for every data path | Test prohibited flows without production secrets |
| Require approval for destructive actions | API-01 flags potentially destructive operations | Ordered allow/ask/deny rules and approval callback | Test rejection, approval and bypass; organizations set authority |
| Secure MCP servers and tools | MCP-02 config auth/TLS hints; MCP-03 declared capability combinations; MCP-01 currently SKIPs | MCP adapter gates routed calls; gateway helper is not a running gateway | Dedicated external MCP attack coverage is future work |
| Maintain trustworthy evidence | Signed packets, SKIPs and exceptions | Memory events; configured external sinks; signed log export | Trust the signer separately and review coverage |
| Control dependencies | Repository CI audits pinned sets and optional extras; not a Verify runtime check | Same repository audit process | Audit resolved installations and container layers separately |
| Understand agent-to-agent access | No complete graph or cascade assessment | Single-hop delegation context | Charter graph, observed-vs-declared access and cascade testing are future work |

## Proposed next scope: MCP servers as first-class Verify targets

**Proposal, not an implemented CLI.** Keep agents first, add MCP servers next,
then skills, APIs, CLI tools and code. A target selector such as
`--target-type agent|mcp` should be distinct from the environment selector; settle
naming and audit schema before implementation. Current commands still require
`--agent-id` and have no standalone MCP target mode.

Record each MCP server's identity, transport, execution environment, exposed tools,
downstream services, effective permissions and evidence source. Run runtime checks
with the server's actual identity and isolation. For remote services without
runtime access, report that evidence as unavailable instead of attributing the
client's runtime results to the server.

Start with:

- Shared runtime checks: identity, filesystem, secrets, persistence and egress.
- Transport-specific controls: stdio subprocess permissions and inherited
  credentials versus HTTP authentication, TLS and request authorization.
- Per-tool access: required scopes, read/write/destructive capabilities and
  authorization enforcement. Separate declared metadata from observed facts.
- HTTP token handling: validate intended audience and prevent passing the client's
  token through to downstream services. See the official
  [MCP authorization security considerations](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx).
- Coverage: explicit PASS/FAIL/SKIP with reasons, probe identity and scope.
  Missing runtime access must not become a PASS.

Passive inspection should not launch arbitrary configured commands or invoke tools.
Require an explicit live-test option and authorized test environment for active
probes. Adversarial tool poisoning, injection, authorization bypass and exfiltration
scenarios belong in Drill's external MCP test suite. Later, Charter can compare
declared relationships and permissions with the observed evidence.
