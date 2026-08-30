// ============================================================
// KAVACH C++ Dynamic Analysis Service
// Real in-browser compilation via Compiler Explorer (Godbolt) API
// + fuzz input testing with line-level matching from sanitizer output.
// API: https://godbolt.org/api  — CORS-enabled, structured JSON responses
// ============================================================

export type CppSanitizer = 'none' | 'asan' | 'ubsan' | 'asan+ubsan';
export type CppFuzzStrategy = 'BOUNDARY' | 'OVERFLOW' | 'FORMAT_STRING' | 'RANDOM' | 'STRESS' | 'NEGATIVE';
export type CppCompileStatus = 'SUCCESS' | 'ERROR' | 'WARNING';
export type CppRunStatus = 'OK' | 'CRASH' | 'TIMEOUT' | 'SANITIZER_ERROR' | 'RUNTIME_ERROR';

export interface CppLineHit {
  line: number;
  column?: number;
  message: string;
  kind: 'CRASH' | 'UB' | 'ERROR' | 'WARNING' | 'INFO';
  inputTrigger: string;
}

export interface CppCompileResult {
  status: CppCompileStatus;
  compilerOutput: string;
  lineErrors: CppLineHit[];
  duration: number;
}

export interface CppFuzzCase {
  id: string;
  input: string;
  strategy: CppFuzzStrategy;
  label: string;
  runStatus: CppRunStatus;
  stdout: string;
  stderr: string;
  exitCode: number;
  lineHits: CppLineHit[];
  durationMs: number;
  interesting: boolean;
  interestingReason?: string;
}

export interface CppDynamicResult {
  sessionId: string;
  sourceCode: string;
  compileResult: CppCompileResult;
  fuzzCases: CppFuzzCase[];
  lineHeatmap: Map<number, CppLineHit[]>;
  totalCrashes: number;
  totalUB: number;
  totalInteresting: number;
  coverageLines: number[];
  timestamp: string;
  compiler: string;
  sanitizer: CppSanitizer;
}

// ---- Compiler Explorer (Godbolt) API integration ----
// Docs: https://godbolt.org/api  — returns structured JSON, CORS-enabled

const GODBOLT_COMPILER = 'g141'; // GCC 14.1
const GODBOLT_API = `https://godbolt.org/api/compiler/${GODBOLT_COMPILER}/compile`;

interface GodboltTextLine { text: string; tag?: { line: number; column: number; text: string } }

interface GodboltResponse {
  code: number;           // exit code of program (or build)
  timedOut: boolean;
  didExecute: boolean;
  stdout: GodboltTextLine[];
  stderr: GodboltTextLine[];
  buildResult?: {
    code: number;
    stdout: GodboltTextLine[];
    stderr: GodboltTextLine[];
    timedOut: boolean;
  };
}

function sanitizerFlags(sanitizer: CppSanitizer): string {
  switch (sanitizer) {
    case 'asan':       return '-fsanitize=address -fno-omit-frame-pointer -g -O1';
    case 'ubsan':      return '-fsanitize=undefined -fno-omit-frame-pointer -g -O1';
    case 'asan+ubsan': return '-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1';
    default:           return '-g -O1';
  }
}

function buildGodboltBody(code: string, sanitizer: CppSanitizer, stdin: string) {
  return {
    source: code,
    options: {
      userArguments: sanitizerFlags(sanitizer),
      executeParameters: { args: [], stdin },
      compilerOptions: { executorRequest: true },
      filters: { execute: true },
      tools: [],
      libraries: [],
    },
    lang: 'c++',
    allowStoreCodeDebug: false,
  };
}

async function godboltFetch(body: object): Promise<GodboltResponse | null> {
  try {
    const resp = await fetch(GODBOLT_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
    // Guard: always read as text first to avoid SyntaxError on HTML error pages
    const text = await resp.text();
    if (!resp.ok || !text.startsWith('{')) {
      console.warn('Godbolt non-JSON response:', resp.status, text.slice(0, 200));
      return null;
    }
    return JSON.parse(text) as GodboltResponse;
  } catch (e) {
    console.error('Godbolt fetch error:', e);
    return null;
  }
}

function extractText(lines: GodboltTextLine[]): string {
  // Strip ANSI color codes from Godbolt output
  return lines
    .map(l => l.text.replace(/\x1b\[[0-9;]*m/g, ''))
    .join('\n');
}

export async function compileCpp(
  code: string,
  sanitizer: CppSanitizer = 'ubsan'
): Promise<{ compileResult: CppCompileResult; ok: boolean }> {
  const start = Date.now();
  const raw = await godboltFetch(buildGodboltBody(code, sanitizer, ''));

  if (!raw) {
    return {
      ok: false,
      compileResult: {
        status: 'ERROR',
        compilerOutput: 'Could not reach Compiler Explorer API. Check network connectivity.',
        lineErrors: [],
        duration: Date.now() - start,
      },
    };
  }

  // Build errors come from buildResult.stderr when executorRequest=true
  const buildStderr = extractText(raw.buildResult?.stderr ?? raw.stderr ?? []);
  const buildStdout = extractText(raw.buildResult?.stdout ?? raw.stdout ?? []);
  const compilerOutput = [buildStdout, buildStderr].filter(Boolean).join('\n');
  const buildCode = raw.buildResult?.code ?? raw.code;
  const hasError = buildCode !== 0 || /error:/i.test(buildStderr);
  const lineErrors = parseLineHitsFromOutput(compilerOutput, '');

  return {
    ok: !hasError,
    compileResult: {
      status: hasError ? 'ERROR' : /warning:/i.test(compilerOutput) ? 'WARNING' : 'SUCCESS',
      compilerOutput: compilerOutput || '(no compiler output)',
      lineErrors,
      duration: Date.now() - start,
    },
  };
}

export async function runWithInput(
  code: string,
  input: string,
  sanitizer: CppSanitizer,
  strategy: CppFuzzStrategy
): Promise<CppFuzzCase> {
  const start = Date.now();
  const id = `fuzz-${Math.random().toString(36).slice(2, 9)}`;
  const raw = await godboltFetch(buildGodboltBody(code, sanitizer, input));

  if (!raw) {
    return {
      id, input, strategy,
      label: strategyLabel(strategy),
      runStatus: 'RUNTIME_ERROR',
      stdout: '', stderr: 'Compiler Explorer API unreachable.',
      exitCode: -1, lineHits: [],
      durationMs: Date.now() - start,
      interesting: false,
    };
  }

  const stdout = extractText(raw.stdout);
  // Runtime stderr (sanitizer output) is in raw.stderr when executorRequest=true
  const stderr  = extractText(raw.stderr);
  const exitCode = raw.code;
  const timedOut = raw.timedOut;

  const lineHits = parseLineHitsFromOutput(stderr, input);

  let runStatus: CppRunStatus = 'OK';
  let interesting = false;
  let interestingReason: string | undefined;

  if (timedOut) {
    runStatus = 'TIMEOUT';
    interesting = true;
    interestingReason = 'Execution timed out';
  } else if (/runtime error:|AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow/i.test(stderr)) {
    runStatus = 'SANITIZER_ERROR';
    interesting = true;
    interestingReason = 'Sanitizer detected undefined behavior or memory error';
  } else if (/signal|SIGSEGV|segmentation fault|Aborted/i.test(stderr)) {
    runStatus = 'CRASH';
    interesting = true;
    interestingReason = 'Process crashed (signal/segfault)';
  } else if (exitCode !== 0) {
    runStatus = 'RUNTIME_ERROR';
    interesting = true;
    interestingReason = `Non-zero exit code: ${exitCode}`;
  }

  return {
    id, input, strategy,
    label: strategyLabel(strategy),
    runStatus, stdout, stderr, exitCode, lineHits,
    durationMs: Date.now() - start,
    interesting, interestingReason,
  };
}

// ---- Fuzz input generators ----

export function generateFuzzInputs(strategy: CppFuzzStrategy, count: number = 8): string[] {
  switch (strategy) {
    case 'BOUNDARY':
      return [
        '0', '1', '-1', '2147483647', '-2147483648',
        '2147483648', '-2147483649', '0.0',
        '', ' ', '\n', '\t',
        String.fromCharCode(0), 'a'.repeat(1024),
      ].slice(0, count);

    case 'OVERFLOW':
      return [
        'A'.repeat(256),
        'A'.repeat(512),
        'A'.repeat(1024),
        'A'.repeat(4096),
        '%s%s%s%s%s',
        '\xff\xfe\x00\x01',
        '9'.repeat(64),
        '-9'.repeat(32),
      ].slice(0, count);

    case 'FORMAT_STRING':
      return [
        '%s', '%d', '%x', '%n',
        '%s%s%s%s%s%s%s%s',
        '%08x.%08x.%08x.%08x',
        '%.1000d', '%1000x',
      ].slice(0, count);

    case 'NEGATIVE':
      return [
        '-1', '-100', '-2147483648', '-9999999999',
        '-0', '-0.0', '-.5', '-1.7976931348623157e+308',
      ].slice(0, count);

    case 'STRESS':
      return Array.from({ length: count }, (_, i) => {
        const size = Math.pow(2, i + 1);
        return String(size);
      });

    case 'RANDOM':
    default: {
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`\'"\\';
      return Array.from({ length: count }, () => {
        const len = Math.floor(Math.random() * 64) + 1;
        return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
      });
    }
  }
}

// ---- Output parser: extract line numbers from sanitizer/compiler output ----

export function parseLineHitsFromOutput(output: string, inputTrigger: string): CppLineHit[] {
  if (!output) return [];

  const hits: CppLineHit[] = [];
  const lines = output.split('\n');

  // Matches: "source.cpp:23:5: error: ..."  OR  "prog.cc:12: runtime error: ..."
  const linePattern = /(?:prog|source|code|main|input)?\.(?:cpp|cc|c|cxx|h)(?:\s+|:)(\d+)(?::(\d+))?:?\s*(.*)/i;
  // Also: "#0 0x... in main /app/prog.cc:42"
  const framePattern = /#\d+\s+\S+\s+in\s+\w+\s+[^:]+:(\d+)/;

  for (const line of lines) {
    const m = line.match(linePattern);
    if (m) {
      const lineNum = parseInt(m[1], 10);
      const col = m[2] ? parseInt(m[2], 10) : undefined;
      const msg = m[3]?.trim() || line.trim();

      let kind: CppLineHit['kind'] = 'INFO';
      if (/runtime error|undefined behavior|sanitizer/i.test(msg)) kind = 'UB';
      else if (/error:/i.test(msg)) kind = 'ERROR';
      else if (/warning:/i.test(msg)) kind = 'WARNING';
      else if (/crash|segfault|signal/i.test(msg)) kind = 'CRASH';

      if (lineNum > 0 && lineNum < 10000) {
        hits.push({ line: lineNum, column: col, message: msg, kind, inputTrigger });
      }
      continue;
    }

    const fm = line.match(framePattern);
    if (fm) {
      const lineNum = parseInt(fm[1], 10);
      if (lineNum > 0 && lineNum < 10000) {
        hits.push({ line: lineNum, message: line.trim(), kind: 'CRASH', inputTrigger });
      }
    }
  }

  // deduplicate by line number (keep first per line)
  const seen = new Set<number>();
  return hits.filter((h) => {
    if (seen.has(h.line)) return false;
    seen.add(h.line);
    return true;
  });
}

// ---- Build heatmap ----

export function buildLineHeatmap(fuzzCases: CppFuzzCase[]): Map<number, CppLineHit[]> {
  const map = new Map<number, CppLineHit[]>();
  for (const fc of fuzzCases) {
    for (const hit of fc.lineHits) {
      const existing = map.get(hit.line) ?? [];
      existing.push(hit);
      map.set(hit.line, existing);
    }
  }
  return map;
}

// ---- Run full dynamic analysis session ----

export async function runCppDynamicAnalysis(
  sourceCode: string,
  strategies: CppFuzzStrategy[],
  sanitizer: CppSanitizer,
  inputsPerStrategy: number,
  onProgress?: (message: string, done: number, total: number) => void
): Promise<CppDynamicResult> {
  const sessionId = `cpp-dyn-${Date.now()}`;
  const start = Date.now();

  // Step 1: compile
  onProgress?.('Compiling C++ source...', 0, 1);
  const { compileResult, ok } = await compileCpp(sourceCode, sanitizer);

  if (!ok) {
    return {
      sessionId,
      sourceCode,
      compileResult,
      fuzzCases: [],
      lineHeatmap: new Map(),
      totalCrashes: 0,
      totalUB: 0,
      totalInteresting: 0,
      coverageLines: [],
      timestamp: new Date(start).toISOString(),
      compiler: 'gcc-head',
      sanitizer,
    };
  }

  // Step 2: generate all inputs
  const allCases: Array<{ input: string; strategy: CppFuzzStrategy }> = [];
  for (const strategy of strategies) {
    const inputs = generateFuzzInputs(strategy, inputsPerStrategy);
    for (const input of inputs) {
      allCases.push({ input, strategy });
    }
  }

  const total = allCases.length;
  const fuzzCases: CppFuzzCase[] = [];

  // Step 3: run sequentially (API rate limiting)
  for (let i = 0; i < allCases.length; i++) {
    const { input, strategy } = allCases[i];
    onProgress?.(`Running fuzz case ${i + 1}/${total} [${strategy}] input: ${JSON.stringify(input).slice(0, 30)}`, i + 1, total);
    const result = await runWithInput(sourceCode, input, sanitizer, strategy);
    fuzzCases.push(result);

    // Small delay to avoid hammering API
    if (i < allCases.length - 1) {
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  const lineHeatmap = buildLineHeatmap(fuzzCases);
  const coverageLines = Array.from(
    new Set(fuzzCases.flatMap((fc) => fc.lineHits.map((h) => h.line)))
  ).sort((a, b) => a - b);

  return {
    sessionId,
    sourceCode,
    compileResult,
    fuzzCases,
    lineHeatmap,
    totalCrashes: fuzzCases.filter((f) => f.runStatus === 'CRASH').length,
    totalUB: fuzzCases.filter((f) => f.runStatus === 'SANITIZER_ERROR').length,
    totalInteresting: fuzzCases.filter((f) => f.interesting).length,
    coverageLines,
    timestamp: new Date(start).toISOString(),
    compiler: 'gcc-head',
    sanitizer,
  };
}

function strategyLabel(s: CppFuzzStrategy): string {
  switch (s) {
    case 'BOUNDARY': return 'Boundary Values';
    case 'OVERFLOW': return 'Buffer Overflow';
    case 'FORMAT_STRING': return 'Format String';
    case 'NEGATIVE': return 'Negative Values';
    case 'STRESS': return 'Stress / Large Input';
    case 'RANDOM': return 'Random Mutation';
  }
}

// ---- Demo C++ templates ----

export const CPP_DEMO_PROGRAMS: Record<string, { label: string; code: string; description: string }> = {
  buffer_overflow: {
    label: 'Buffer Overflow (strcpy)',
    description: 'Classic stack buffer overflow via unbounded strcpy. UBSan/ASan will detect this.',
    code: `#include <iostream>
#include <cstring>

void processInput(const char* input) {
    char buffer[64];
    strcpy(buffer, input);  // VULNERABLE: no bounds check
    std::cout << "Processed: " << buffer << std::endl;
}

int main() {
    std::string input;
    std::cin >> input;
    processInput(input.c_str());
    return 0;
}`,
  },
  integer_overflow: {
    label: 'Integer Overflow',
    description: 'Signed integer overflow — undefined behavior in C++. UBSan catches this.',
    code: `#include <iostream>

int multiply(int a, int b) {
    return a * b;  // VULNERABLE: signed overflow is UB
}

int main() {
    int x;
    std::cin >> x;
    int result = multiply(x, 1000000);
    std::cout << "Result: " << result << std::endl;
    return 0;
}`,
  },
  format_string: {
    label: 'Format String Bug (printf)',
    description: 'User input passed directly to printf format argument.',
    code: `#include <cstdio>
#include <cstring>

void logMessage(const char* msg) {
    printf(msg);  // VULNERABLE: format string injection
    printf("\\n");
}

int main() {
    char input[256];
    if (fgets(input, sizeof(input), stdin)) {
        // strip newline
        size_t len = strlen(input);
        if (len > 0 && input[len-1] == '\\n') input[len-1] = '\\0';
        logMessage(input);
    }
    return 0;
}`,
  },
  null_deref: {
    label: 'Null Pointer Dereference',
    description: 'Missing null check before pointer dereference.',
    code: `#include <iostream>
#include <string>

struct Node {
    int value;
    Node* next;
};

Node* findNode(Node* head, int target) {
    while (head != nullptr) {
        if (head->value == target) return head;
        head = head->next;
    }
    return nullptr;  // not found
}

int main() {
    Node n1{42, nullptr};
    int target;
    std::cin >> target;
    Node* result = findNode(&n1, target);
    // VULNERABLE: no null check
    std::cout << "Found: " << result->value << std::endl;
    return 0;
}`,
  },
  division_by_zero: {
    label: 'Division by Zero',
    description: 'Integer division without zero check — crash on input 0.',
    code: `#include <iostream>

double safeDivide(double numerator, double denominator) {
    return numerator / denominator;  // VULNERABLE: no zero check
}

int main() {
    double a, b;
    std::cin >> a >> b;
    std::cout << "Result: " << safeDivide(a, b) << std::endl;
    return 0;
}`,
  },
};
