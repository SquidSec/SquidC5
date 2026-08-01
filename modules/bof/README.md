# Official BOF-style modules (authorized lab)

Compile with mingw COFF toolchain. Native `sc5beacon` loads via `bof:run` when `SC5_ALLOW_BOF=1`.

| Module | Purpose |
|--------|---------|
| whoami | Identity |
| env | Environment (limited keys) |
| dir | Directory list |
| net | Network stub |
| screenshot | Capture stub (no-op default) |

```text
# queue from server
POST /api/v1/modules/bof/run  {"session_id":"...","module_id":"whoami"}
```

Object bytes optional (`object_b64`); without bytes the agent **simulates** catalog modules safely.
