# Pull Request Review — 2026-08-13

- [x] Resolve the newly opened pull request and read its title, description, commits, and full diff.
- [x] Check scope, test coverage, commit clarity, security boundaries, regressions, and scalability concerns.
- [x] Run targeted verification for claims and suspicious paths in the patch.
- [x] Post a specific GitHub review: request changes for material concerns, otherwise approve.
- [x] Record the reviewed PR, findings, verification evidence, and submitted review below.

## Review

Reviewed `moisesja/crypto-dotnet` PR #27, commit
`34272d1f8abbdb776a8922c4cc0222915b706639`:

- Title: `feat: ICapableKeyStore custody surface — release 1.6.0 (closes #26)`.
- Scope: 36 files, 7,115 insertions, 10 deletions, one commit; security-critical custody,
  signing, BBS, import, idempotency, namespace, and release changes.
- The commit message is clear, but the PR is too broad for one security-sensitive review unit.
- Existing tests are extensive, but four missing boundary cases were reproduced by an isolated
  `/tmp/pr27-review` executable harness:

  ```text
  CAPABILITY_WITH: operation=Generate; algorithm=es256-p1363
  BBS_SELF_CERTIFICATION: accepted=True; length=80
  IMPORT_EXCEPTION: type=System.DllNotFoundException; consumed=True
  BBS_COUNT: type=System.OutOfMemoryException
  ```

- Blocking findings:
  1. BBS output is verified by the same injected provider that produced it, allowing a provider
     to return arbitrary 80-byte output and certify it itself.
  2. `ImportAsync` leaks backend/platform exceptions from `IKeyGenerator.FromPrivateKey` instead
     of mapping them to `KeyStoreException(Unavailable)`.
  3. `KeyStoreCapability` can be rewritten by `with` into an invalid operation/algorithm pair.
  4. BBS has no message-count resource bound and allocates by untrusted `Count` before checking
     total payload bytes, allowing `OutOfMemoryException` with zero-byte messages.
- Repository test run: `dotnet test NetCrypto.sln -c Release --no-restore --filter
  "Category!=NativeFFI" --tl:off` produced 1,152 passes and the five expected
  `BbsUnavailableTests` failures because the native BBS library is present locally, matching the
  PR's disclosed environment-dependent failures.
- The GitHub connector's review write failed with HTTP 403, so the authenticated `gh pr review`
  fallback posted a blocking `COMMENTED` review:
  <https://github.com/moisesja/crypto-dotnet/pull/27#pullrequestreview-4928320731>.
- The repository-required independent adversarial subagent was attempted twice but blocked by
  its safety classifier before execution; none of its output was treated as evidence. All four
  reported findings were independently reproduced by the primary review harness.

## Re-review — 2026-08-13

- [x] Inspect every commit and changed line added after reviewed commit `34272d1`.
- [x] Re-run the original four reproducers and verify their regression tests.
- [x] Run focused and full relevant test/build checks.
- [x] Independently probe the revised BBS, import, capability-invariant, count-bound, and
  reentrancy paths for new boundary failures.
- [x] Post an updated GitHub verdict and record the exact evidence below.

Reviewed follow-up commits `f218afe` and `b847152` (PR head `b847152a8d4b880a7eb7c7a8da97615f30af8838`).

Confirmed fixed:

- capability operation/algorithm `with` invariant;
- absurd/negative BBS message-count rejection;
- `DllNotFoundException` import normalization;
- BBS independent verification when the native default provider is loadable;
- legacy sign documentation and generate reentrancy ordering.

Remaining blockers, reproduced by both the primary `/tmp/pr27-review` harness and an independent
`/tmp/pr27-probes` pass:

1. Without the native BBS library, the store falls back to the producing provider for verify;
   a provider lying in both `Sign` and `Verify` successfully returns arbitrary 80-byte output.
2. Exception normalization still leaks backend `ObjectDisposedException` during import, and
   backend `ObjectDisposedException`, fabricated `OperationCanceledException`, and internal
   `ArgumentException` during request-based generation.
3. The BBS byte total is checked only after all messages are copied. A 4096-entry list returning
   300 KB values was read 21 times instead of rejecting after the fourth; inconsistent indexers
   can also leak `IndexOutOfRangeException`.

Verification:

- `dotnet build src/NetCrypto/NetCrypto.csproj -c Release --no-restore -warnaserror --tl:off
  --disable-build-servers` → 0 warnings, 0 errors.
- Focused key-store/capability/import/BBS suite → 157 passed.
- Independent pass: 1202 non-BBS-absent tests passed; the five standard full-run failures remain
  only the known `BbsUnavailableTests` mismatch when the native library is present.

Updated blocking review posted:
<https://github.com/moisesja/crypto-dotnet/pull/27#pullrequestreview-4928818815>.
