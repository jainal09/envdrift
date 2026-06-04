export const meta = {
  name: 'coverage-orchestrator',
  description: 'Lift below-threshold source files to target coverage: fan out test-writers, SQA-review each, index to Obsidian',
  whenToUse: 'When you have a list of source files below a coverage threshold and want tests written, reviewed, and documented in parallel',
  phases: [
    { title: 'Plan', detail: 'confirm targets and baseline' },
    { title: 'Write Tests', detail: 'one writer subagent per target file' },
    { title: 'SQA Review', detail: 'one reviewer subagent per target file' },
    { title: 'Index', detail: 'index each file\'s work to the Obsidian coverage-issue folder' },
  ],
}

// args = {
//   targets: [{ path, pct, missing, missingLines: [..] }],
//   obsidianDir: '<absolute path to coverage-issue folder>',
//   overallBefore: 87.02,
//   threshold: 85,
// }
const cfg = typeof args === 'string' ? JSON.parse(args) : args
const targets = cfg.targets
const OBSIDIAN = cfg.obsidianDir
const THRESHOLD = cfg.threshold ?? 85

const WRITER_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['path', 'testFile', 'testsAdded', 'targetedLines', 'passed', 'summary'],
  properties: {
    path: { type: 'string', description: 'source file under test' },
    testFile: { type: 'string', description: 'path to the new/edited test file' },
    testsAdded: { type: 'integer', description: 'number of test functions added' },
    targetedLines: { type: 'array', items: { type: 'integer' }, description: 'previously-missing source line numbers the new tests exercise' },
    passed: { type: 'boolean', description: 'true if the new test file passes pytest with no failures' },
    lintClean: { type: 'boolean', description: 'true if ruff + pyrefly pass on the test file' },
    summary: { type: 'string', description: 'one-paragraph summary of what was tested and how' },
  },
}

const SQA_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['path', 'approved', 'severity', 'issuesFound', 'fixesApplied', 'finalPassed', 'verdict'],
  properties: {
    path: { type: 'string' },
    approved: { type: 'boolean', description: 'true if tests are meaningful and ready to ship' },
    severity: { type: 'string', enum: ['none', 'minor', 'major'] },
    issuesFound: { type: 'array', items: { type: 'string' } },
    fixesApplied: { type: 'array', items: { type: 'string' } },
    finalPassed: { type: 'boolean', description: 'pytest still green after any SQA fixes' },
    verdict: { type: 'string', description: 'one-paragraph reviewer verdict' },
  },
}

const INDEX_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['path', 'notePath', 'written'],
  properties: {
    path: { type: 'string' },
    notePath: { type: 'string' },
    written: { type: 'boolean' },
  },
}

log(`Orchestrating ${targets.length} below-${THRESHOLD}% files. Overall baseline: ${cfg.overallBefore}%`)

const results = await pipeline(
  targets,

  // ---- Stage 1: Write Tests ----
  (t) => agent(
    `You are a Python test-writer for the "envdrift" project (repo root /Users/jainal09/envdrift, package src/envdrift, run everything with \`uv run\`).

TARGET SOURCE FILE: ${t.path}
Current line coverage: ${t.pct}% — ${t.missing} uncovered lines.
Previously-uncovered line numbers to exercise: ${JSON.stringify(t.missingLines)}

GOAL: Add real, meaningful unit tests that exercise as many of those uncovered lines as practical, aiming to bring this file to >=${THRESHOLD}% line coverage. Quality matters more than hitting every line — never write filler like \`assert True\` or tests that only construct an object. Each test must assert on real behavior.

RULES:
1. Read the source file first: ${t.path}. Understand what the uncovered lines do (error branches, edge cases, CLI flags, exception handling, platform guards, etc.).
2. Study existing test conventions before writing: look at tests/conftest.py (shared fixtures), tests/helpers.py (DummyEncryptionBackend), and 1-2 existing test files that cover similar code (e.g. tests/unit/test_*.py, tests/scanner/test_*.py). Match the project's mocking style: pytest monkeypatch first, unittest.mock.patch/MagicMock where needed, typer.testing.CliRunner for CLI commands. Reuse existing fixtures.
3. CREATE A NEW DEDICATED TEST FILE so parallel writers never touch the same file. Put it at tests/unit/coverage/test_cov_<sanitized_module>.py where <sanitized_module> is the source path under src/envdrift/ with slashes replaced by underscores and .py dropped (e.g. src/envdrift/scanner/kingfisher.py -> tests/unit/coverage/test_cov_scanner_kingfisher.py). Do NOT edit any existing test file. The tests/unit/coverage/ directory may not exist yet — create it.
4. Do NOT modify any source file under src/. Tests only.
5. Mock external processes/network/binaries (subprocess, boto3, hvac, azure, requests, docker, dotenvx/sops CLIs). Tests must be hermetic and fast — no real network, no real docker, no integration markers.
6. Validate before returning, all with \`uv run\`:
   - \`uv run pytest <your_test_file> --no-cov -q\`  (must pass, 0 failures)
   - \`uv run ruff check <your_test_file>\`  (fix all issues; tests have relaxed S-rules per pyproject)
   - \`uv run ruff format <your_test_file>\`
   - \`uv run pyrefly check <your_test_file>\`  (fix type errors; if a vault SDK import fails to resolve, that is a known env issue — note it, don't block)
   Iterate until pytest is green and ruff is clean.
7. To confirm you actually moved coverage, you MAY run \`uv run pytest <your_test_file> --cov=envdrift --cov-report=term-missing -q\` and inspect the target file's line — but use a unique COVERAGE_FILE to avoid clobbering peers, e.g. prefix with \`COVERAGE_FILE=/tmp/.cov_<module>\`.

Return the structured result describing what you did. Your final output IS data for the orchestrator, not a message to a human.`,
    { label: `write:${t.path.split('/').pop()}`, phase: 'Write Tests', schema: WRITER_SCHEMA }
  ).then(w => ({ target: t, writer: w })),

  // ---- Stage 2: SQA Review ----
  (r) => {
    if (!r || !r.writer) return null
    const { target: t, writer: w } = r
    return agent(
      `You are a senior SQA reviewer for the "envdrift" project (repo root /Users/jainal09/envdrift, use \`uv run\`).

A test-writer just added tests for source file ${t.path} (was ${t.pct}% covered, ${t.missing} uncovered lines).
Test file produced: ${w.testFile}
Writer's claim: added ${w.testsAdded} tests, passed=${w.passed}, summary: ${w.summary}
Lines they targeted: ${JSON.stringify(w.targetedLines)}

YOUR JOB — review the test file ${w.testFile} critically and verify these properties. Fix MINOR issues yourself (you may Edit the test file); flag MAJOR ones in issuesFound:
1. MEANINGFUL: every test asserts on real behavior/output/exceptions — reject filler (\`assert True\`, bare construction with no assertion, asserting a mock was called without checking effects).
2. CORRECT TARGETING: tests actually exercise the previously-uncovered lines (${JSON.stringify(t.missingLines)}), not just easy already-covered paths. Confirm by running: \`COVERAGE_FILE=/tmp/.covsqa_${t.path.replace(/[^a-z0-9]/gi,'_')} uv run pytest ${w.testFile} --cov=envdrift --cov-report=term-missing -q\` and checking the ${t.path} row improved.
3. HERMETIC: no real network/subprocess/docker; external deps are mocked. No \`@pytest.mark.integration/aws/vault/azure/gcp\`.
4. NO SOURCE EDITS: confirm only the test file changed (\`git status --short src/\` should show nothing from this work).
5. GREEN + CLEAN: \`uv run pytest ${w.testFile} --no-cov -q\` passes; \`uv run ruff check ${w.testFile}\` and \`uv run pyrefly check ${w.testFile}\` are clean. Run ruff format if needed.

If you make fixes, re-run pytest to confirm still green. Set approved=true only if the tests are meaningful, correctly targeted, hermetic, and green/clean. Return the structured verdict.`,
      { label: `sqa:${t.path.split('/').pop()}`, phase: 'SQA Review', schema: SQA_SCHEMA }
    ).then(s => ({ ...r, sqa: s }))
  },

  // ---- Stage 3: Index to Obsidian ----
  (r) => {
    if (!r || !r.sqa) return null
    const { target: t, writer: w, sqa: s } = r
    const slug = t.path.replace('src/envdrift/', '').replace(/[^a-z0-9]/gi, '_')
    const notePath = `${OBSIDIAN}/${slug}.md`
    return agent(
      `You are an indexing agent. Write a concise Obsidian markdown note documenting coverage work, for the user's observability. Use the Write tool to create EXACTLY this file (absolute path, note the spaces in the path are fine):

${notePath}

Note content must be valid markdown with this structure:
- A YAML frontmatter block with: title, source_file, coverage_before, tests_added, sqa_approved (true/false), sqa_severity, status (one of "done"/"needs-attention").
- "## Source file" — ${t.path}, was ${t.pct}% covered with ${t.missing} uncovered lines.
- "## Tests added" — test file ${w.testFile}, ${w.testsAdded} tests. Writer summary: ${JSON.stringify(w.summary)}. Lines targeted: ${JSON.stringify(w.targetedLines)}. pytest passed: ${w.passed}. lint clean: ${w.lintClean}.
- "## SQA review" — approved: ${s.approved}, severity: ${s.severity}, final pytest passed: ${s.finalPassed}. Issues found: ${JSON.stringify(s.issuesFound)}. Fixes applied: ${JSON.stringify(s.fixesApplied)}. Verdict: ${JSON.stringify(s.verdict)}.
- A trailing "Linked from [[coverage-issue-index]]" line.

Set status to "needs-attention" if sqa_approved is false or final pytest did not pass; otherwise "done". After writing, return the structured result.`,
      { label: `index:${t.path.split('/').pop()}`, phase: 'Index', schema: INDEX_SCHEMA }
    ).then(idx => ({ path: t.path, before: t.pct, writer: w, sqa: s, index: idx }))
  }
)

const done = results.filter(Boolean)
return {
  overallBefore: cfg.overallBefore,
  threshold: THRESHOLD,
  filesProcessed: done.length,
  filesApproved: done.filter(d => d.sqa && d.sqa.approved).length,
  needsAttention: done.filter(d => !d.sqa || !d.sqa.approved || !d.sqa.finalPassed).map(d => d.path),
  testFiles: done.map(d => d.writer && d.writer.testFile).filter(Boolean),
  perFile: done.map(d => ({
    path: d.path,
    before: d.before,
    testFile: d.writer && d.writer.testFile,
    testsAdded: d.writer && d.writer.testsAdded,
    approved: d.sqa && d.sqa.approved,
    severity: d.sqa && d.sqa.severity,
    finalPassed: d.sqa && d.sqa.finalPassed,
    note: d.index && d.index.notePath,
  })),
}
