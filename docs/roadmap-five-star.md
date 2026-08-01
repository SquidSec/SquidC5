# Five-star C5 program

Goal: ★★★★★ across implants, traffic, post-ex, multi-player, AI, governance, CI.

**Process:** feature branch → unit tests → PR → CI + SquidGate green → merge `master` → deploy **Release binary** to prod → repeat.

## Pack status (living)

| Pack | Focus | Status |
|------|--------|--------|
| **A** | Native agent, factory, lifecycle, BOF scaffold | **Landed** (sc5beacon v2, build API, CI artifacts) |
| **B** | Traffic, profile push, transforms, SOCKS duplex | **In progress** (transforms + push done; SOCKS reverse-dial duplex this PR) |
| **C** | File chunks, engagement ROE, multi-op | **Landed** (API); ops UI polish ongoing |
| **D** | AI capability pack + local Ollama path | **Landed** (15 caps; local LLM URL/model) |
| **E** | CI proof, SBOM, audit verify, benchmarks | **Landed** (verify, cov, mypy, SBOM, agent CI) |

## Still climbing to full ★★★★★

- Process injection + sleep mask  
- Windows COFF/BOF **loader host**  
- P2P / SMB / named pipe  
- Ops UI file browser / pivot graph  
- Lab victim matrix soak numbers  
- External security audit  

## Links

- [User guide](user-guide.md)  
- [Deployment](deployment.md)  
- [Native beacon](../agents/sc5beacon/README.md)  
- [README](../README.md)  
