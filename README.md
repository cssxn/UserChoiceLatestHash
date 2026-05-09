# UserChoiceLatestHash

Independent C++ implementation for computing and verifying `UserChoiceLatest` hashes.

This project is organized into separate modules:

- `HashTables.cpp`
  Loads the lookup tables.
- `HashCodec.cpp`
  Implements the `7D60` hashing pipeline.
- `RegistryContext.cpp`
  Reads registry context and builds canonical input strings.
- `Cli.cpp`
  Handles command-line modes and formatted output.
- `main.cpp`
  Thin executable entry point.

## Build

From this directory:

```bat
cmd /c "call \"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat\" >nul && cl /nologo /EHsc /W4 /TP /c main.cpp HashTables.cpp HashCodec.cpp RegistryContext.cpp Cli.cpp && link /NOLOGO /OUT:UserChoiceLatestHash.exe main.obj HashTables.obj HashCodec.obj RegistryContext.obj Cli.obj advapi32.lib crypt32.lib"
```
Or use the provided one-click packaging script:

```bat
build_msvc.bat
```
## Usage

### 1. Debug one canonical input

Prints intermediate packed buffer, MD5, and post-mix values:

```bat
UserChoiceLatestHash.exe -debug "<canonical_input>"
```

### 2. Verify a live association from the current machine

For a file extension:

```bat
UserChoiceLatestHash.exe -verify .pdd
```

For a protocol:

```bat
UserChoiceLatestHash.exe -verify http
```

This mode automatically reads:

- `HKLM\SOFTWARE\Microsoft\SQMClient\MachineID`
- current user SID
- `ProgId`
- the target key last write time
- current `Hash`

It then builds the canonical input string, computes the expected hash, and compares it to the registry value.

## Verification logic

`-verify` prefers:

- `UserChoiceLatest`

and falls back to:

- `UserChoice`

## Current assumptions

- The fixed working seeds are constant for the target environment this tool is meant to run against.
- The lookup tables are embedded in `UserChoiceLatestHashTables.inc`.
- The implementation is intended to reproduce the expected hash behavior for this environment, not to be a generic Windows association hash framework.

## Notes

- The hash changes whenever the canonical input changes.
- In practice that usually means the timestamp portion changes when the registry key is recreated.
- If you delete and recreate a test association, do not expect the previous hash to remain stable.

## Example

Known canonical sample:

```text
copyright (c) microsoft. all rights reserved {3822b7ca-c2f4-4889-b8cc-4ce39a8fb81c}.pdd01dcb06ea49f32a0b4deb148-0249-44c4-a8d3-5409e822c599msedgepdfs-1-5-21-673349297-2269585490-1023937497-500
```

Expected output:

```text
JOBZ2dl4dKM=
```

For live verification on a target machine:

```bat
UserChoiceLatestHash.exe -verify .pdd
```

Typical fields in the output:

- `choice`
  Shows whether the tool matched `UserChoiceLatest` or fell back to `UserChoice`.
- `registry_hash`
  The current hash stored in the registry.
- `computed_hash`
  The hash calculated by this implementation.
- `match`
  `true` when both values are identical.

