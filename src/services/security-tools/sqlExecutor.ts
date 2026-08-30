import type { SourceFile } from '@/types';

// ============================================================
// Controlled SQL Execution Engine
//
// Executes constructed SQL queries against an in-memory database.
// When the uploaded source contains CREATE TABLE / INSERT statements,
// those are used to build the schema (SOURCE-DERIVED). Otherwise a
// controlled fixture database with known seed data is used so that
// boolean / UNION / tautology mutations produce observable behavioral
// differences (CONTROLLED SQL FIXTURE VALIDATION).
//
// Authenticity: CONTROLLED — isolated in-browser execution.
// ============================================================

export interface ExecResult {
  rows: Record<string, unknown>[];
  rowCount: number;
  error: string | null;
  executedQuery: string;
  tablesAffected: string[];
  dataExtracted: boolean;
  authBypassed: boolean;
  tableModified: boolean;
  dataModified: boolean;
  syntaxError: boolean;
}

export interface DBSchema {
  tables: { name: string; columns: string[]; rows: Record<string, unknown>[] }[];
  source: 'SOURCE_DERIVED' | 'CONTROLLED_FIXTURE';
}

interface MemoryDB {
  tables: Map<string, { columns: string[]; rows: Record<string, unknown>[] }>;
}

// --- Controlled fixture DB (used when source has no schema) ---

const FIXTURE_SCHEMA: DBSchema = {
  tables: [
    {
      name: 'users',
      columns: ['id', 'username', 'email', 'role'],
      rows: [
        { id: 1, username: 'admin', email: 'admin@example.com', role: 'admin' },
        { id: 2, username: 'alice', email: 'alice@example.com', role: 'user' },
        { id: 3, username: 'bob', email: 'bob@example.com', role: 'user' },
        { id: 4, username: 'charlie', email: 'charlie@example.com', role: 'user' },
        { id: 5, username: 'guest', email: 'guest@example.com', role: 'guest' },
      ],
    },
  ],
  source: 'CONTROLLED_FIXTURE',
};

// Parse source code to extract table schema and seed data
export function extractSchema(source: SourceFile): DBSchema {
  const content = source.content;
  const tables: DBSchema['tables'] = [];

  // Extract CREATE TABLE statements
  const createRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(([^)]+)\)/gi;
  let match: RegExpExecArray | null;

  while ((match = createRegex.exec(content)) !== null) {
    const tableName = match[1];
    const columnDefs = match[2].split(',').map((c) => c.trim());
    const columns = columnDefs
      .map((c) => c.split(/\s+/)[0].replace(/["'`]/g, ''))
      .filter((c) => c && !c.toUpperCase().startsWith('PRIMARY'));

    tables.push({ name: tableName, columns, rows: [] });
  }

  // Extract INSERT statements
  const insertRegex = /INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/gi;
  while ((match = insertRegex.exec(content)) !== null) {
    const tableName = match[1];
    const colNames = match[2].split(',').map((c) => c.trim());
    const values = match[3].split(',').map((v) => v.trim());

    const table = tables.find((t) => t.name === tableName);
    if (table) {
      const row: Record<string, unknown> = {};
      colNames.forEach((col, i) => {
        const val = values[i] || '';
        const cleaned = val.replace(/^['"]|['"]$/g, '');
        row[col] = /^\d+$/.test(cleaned) ? parseInt(cleaned, 10) : cleaned;
      });
      table.rows.push(row);
    }
  }

  // If source has tables with rows, use source-derived schema.
  // If source has tables but no rows, still use source schema but seed with fixture data.
  // If no tables at all, fall back to controlled fixture.
  if (tables.length > 0) {
    // If a users table exists but has no rows, seed it from the fixture
    for (const t of tables) {
      if (t.rows.length === 0 && t.name === 'users') {
        t.rows.push(...FIXTURE_SCHEMA.tables[0].rows.map((r) => ({ ...r })));
      }
    }
    return { tables, source: 'SOURCE_DERIVED' };
  }

  return { ...FIXTURE_SCHEMA, source: 'CONTROLLED_FIXTURE' };
}

function createMemoryDB(schema: DBSchema): MemoryDB {
  const tables = new Map<string, { columns: string[]; rows: Record<string, unknown>[] }>();
  for (const t of schema.tables) {
    tables.set(t.name, { columns: t.columns, rows: [...t.rows.map((r) => ({ ...r }))] });
  }
  return { tables };
}

// Execute a SELECT query against the in-memory DB
function executeSelect(db: MemoryDB, query: string): { rows: Record<string, unknown>[]; error: string | null; tablesAffected: string[]; syntaxError: boolean } {
  const tablesAffected: string[] = [];

  // Normalize: strip trailing comments but keep query structure
  // Remove -- comments that start at end of line (not inside strings)
  const cleaned = query.replace(/--[^\n]*$/gm, '').replace(/#[^\n]*$/gm, '').trim();
  if (!cleaned) return { rows: [], error: 'Empty query after comment removal', tablesAffected, syntaxError: true };

  // Remove trailing semicolon
  const trimmed = cleaned.replace(/;+$/, '').trim();
  if (!trimmed) return { rows: [], error: 'Empty query', tablesAffected, syntaxError: true };

  // Check for UNION
  const unionMatch = trimmed.match(/SELECT\s+(.*?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.*?))?\s+UNION\s+(?:ALL\s+)?SELECT\s+(.*)/is);
  if (unionMatch) {
    const tableName = unionMatch[2];
    const whereClause = unionMatch[3];
    const table = db.tables.get(tableName);
    if (!table) return { rows: [], error: `Table "${tableName}" not found`, tablesAffected, syntaxError: false };

    tablesAffected.push(tableName);

    // Get base rows matching WHERE
    let baseRows = table.rows;
    if (whereClause) {
      const filtered = filterRows(baseRows, whereClause);
      if (filtered.syntaxError) return { rows: [], error: filtered.error, tablesAffected, syntaxError: true };
      baseRows = filtered.rows;
    }

    // Parse UNION columns — we just return the injected data
    const unionPart = unionMatch[4];
    const unionCols = parseUnionColumns(unionPart, db);

    // Combine base rows with union rows
    const allRows = [...baseRows, ...unionCols];
    return { rows: allRows, error: null, tablesAffected, syntaxError: false };
  }

  // Simple SELECT with WHERE
  const selectMatch = trimmed.match(/SELECT\s+(.*?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.*?))?$/is);
  if (selectMatch) {
    const cols = selectMatch[1].trim();
    const tableName = selectMatch[2].trim();
    const whereClause = selectMatch[3]?.trim();

    const table = db.tables.get(tableName);
    if (!table) return { rows: [], error: `Table "${tableName}" not found`, tablesAffected, syntaxError: false };

    tablesAffected.push(tableName);

    let rows = table.rows;
    if (whereClause) {
      const filtered = filterRows(rows, whereClause);
      if (filtered.syntaxError) return { rows: [], error: filtered.error, tablesAffected, syntaxError: true };
      rows = filtered.rows;
    }

    if (cols === '*') {
      return { rows, error: null, tablesAffected, syntaxError: false };
    }

    // Select specific columns
    const colNames = cols.split(',').map((c) => c.trim());
    const projected = rows.map((r) => {
      const out: Record<string, unknown> = {};
      for (const c of colNames) {
        out[c] = r[c];
      }
      return out;
    });
    return { rows: projected, error: null, tablesAffected, syntaxError: false };
  }

  return { rows: [], error: `Unparseable query: ${trimmed.substring(0, 80)}`, tablesAffected, syntaxError: true };
}

// Execute DROP TABLE
function executeDrop(db: MemoryDB, query: string): { error: string | null; tablesAffected: string[]; syntaxError: boolean } {
  const match = query.match(/DROP\s+TABLE\s+(\w+)/i);
  if (match) {
    const tableName = match[1];
    if (db.tables.has(tableName)) {
      db.tables.delete(tableName);
      return { error: null, tablesAffected: [tableName], syntaxError: false };
    }
    return { error: `Table "${tableName}" not found`, tablesAffected: [], syntaxError: false };
  }
  return { error: 'Invalid DROP statement', tablesAffected: [], syntaxError: true };
}

// Execute INSERT
function executeInsert(db: MemoryDB, query: string): { error: string | null; tablesAffected: string[]; syntaxError: boolean } {
  const match = query.match(/INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/is);
  if (match) {
    const tableName = match[1];
    const table = db.tables.get(tableName);
    if (!table) return { error: `Table "${tableName}" not found`, tablesAffected: [], syntaxError: false };

    const cols = match[2].split(',').map((c) => c.trim());
    const vals = match[3].split(',').map((v) => v.trim().replace(/^['"]|['"]$/g, ''));
    const row: Record<string, unknown> = {};
    cols.forEach((c, i) => { row[c] = vals[i]; });
    table.rows.push(row);
    return { error: null, tablesAffected: [tableName], syntaxError: false };
  }
  return { error: 'Invalid INSERT', tablesAffected: [], syntaxError: true };
}

function filterRows(rows: Record<string, unknown>[], whereClause: string): { rows: Record<string, unknown>[]; syntaxError: boolean; error: string | null } {
  // Strip SQL line comments (-- to end of line) before parsing
  const commentStripped = whereClause.replace(/--.*$/g, '').trim();
  if (!commentStripped) {
    // Entire WHERE clause was commented out — return all rows (no filter)
    return { rows, syntaxError: false, error: null };
  }

  // Detect unbalanced quotes in the comment-stripped clause
  const singleQuotes = (commentStripped.match(/'/g) || []).length;
  const doubleQuotes = (commentStripped.match(/"/g) || []).length;
  if (singleQuotes % 2 !== 0 || doubleQuotes % 2 !== 0) {
    return { rows: [], syntaxError: true, error: `Unbalanced quotes in WHERE clause: ${commentStripped.substring(0, 60)}` };
  }

  // Handle OR 1=1 / OR '1'='1' (returns all rows)
  if (/or\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i.test(commentStripped) || /or\s+1\s*=\s*1/i.test(commentStripped)) {
    return { rows, syntaxError: false, error: null };
  }

  // Handle AND 1=1 (tautology — returns original filter result)
  // Handle AND 1=0 (contradiction — returns no rows)
  if (/and\s+1\s*=\s*0/i.test(commentStripped) || /and\s+['"]?1['"]?\s*=\s*['"]?0['"]?/i.test(commentStripped)) {
    return { rows: [], syntaxError: false, error: null };
  }
  // Strip AND 1=1 / AND '1'='1' tautology — it doesn't change the result
  const stripped = commentStripped.replace(/and\s+['"]?1['"]?\s*=\s*['"]?1['"]?/gi, '').trim();

  // Handle column = 'value'
  const match = stripped.match(/(\w+)\s*=\s*['"]?(.*?)['"]?$/i);
  if (match) {
    const col = match[1];
    const val = match[2].replace(/['"]$/g, '');
    return { rows: rows.filter((r) => String(r[col]) === val), syntaxError: false, error: null };
  }

  // Can't parse — return all rows as fallback (conservative)
  return { rows, syntaxError: false, error: null };
}

function parseUnionColumns(unionSelect: string, db: MemoryDB): Record<string, unknown>[] {
  // Check if UNION selects from another table
  const tableMatch = unionSelect.match(/FROM\s+(\w+)/i);
  if (tableMatch) {
    const tableName = tableMatch[1];
    const table = db.tables.get(tableName);
    if (table) return table.rows.map((r) => ({ ...r }));
  }

  // Literal values in UNION SELECT
  const cols = unionSelect.split(',').map((c) => c.trim());
  const row: Record<string, unknown> = {};
  cols.forEach((c, i) => {
    const cleaned = c.replace(/^['"]|['"]$/g, '');
    row[`col_${i}`] = cleaned;
  });
  return [row];
}

// Main execution function — runs a query against a fresh DB instance
export function executeQuery(query: string, schema: DBSchema): ExecResult {
  const db = createMemoryDB(schema);
  const normalized = query.trim();

  // Handle stacked queries (split by semicolon)
  const statements = normalized.split(';').map((s) => s.trim()).filter((s) => s.length > 0);

  let lastRows: Record<string, unknown>[] = [];
  let lastError: string | null = null;
  let hadSyntaxError = false;
  const allTablesAffected: string[] = [];

  for (const stmt of statements) {
    const upper = stmt.toUpperCase();

    if (upper.startsWith('SELECT')) {
      const result = executeSelect(db, stmt);
      lastRows = result.rows;
      lastError = result.error;
      if (result.syntaxError) hadSyntaxError = true;
      allTablesAffected.push(...result.tablesAffected);
    } else if (upper.startsWith('DROP')) {
      const result = executeDrop(db, stmt);
      lastError = result.error;
      if (result.syntaxError) hadSyntaxError = true;
      allTablesAffected.push(...result.tablesAffected);
    } else if (upper.startsWith('INSERT')) {
      const result = executeInsert(db, stmt);
      lastError = result.error;
      if (result.syntaxError) hadSyntaxError = true;
      allTablesAffected.push(...result.tablesAffected);
    } else if (upper.startsWith('DELETE')) {
      const match = stmt.match(/DELETE\s+FROM\s+(\w+)/i);
      if (match) {
        const tableName = match[1];
        const table = db.tables.get(tableName);
        if (table) {
          table.rows = [];
          allTablesAffected.push(tableName);
        }
      }
    } else {
      lastError = `Unsupported statement: ${upper.substring(0, 20)}`;
      hadSyntaxError = true;
    }
  }

  // Analyze results for injection indicators
  const hasUnion = statements.some((s) => /UNION/i.test(s));
  const dataExtracted = lastRows.length > 0 && hasUnion;
  const hasTautology = /OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?/i.test(normalized) || /OR\s+1\s*=\s*1/i.test(normalized);

  // authBypassed: tautology caused more rows than the fixture would return for a single-user lookup,
  // OR a UNION injected extra rows, OR a DROP removed a table
  const authBypassed =
    (hasTautology && lastRows.length > 1) ||
    (hasUnion && lastRows.length > 0) ||
    allTablesAffected.some((t) => !db.tables.get(t));

  const tableModified = allTablesAffected.some((t) => {
    const table = db.tables.get(t);
    return !table; // Table was dropped
  });

  // dataModified: an INSERT/DELETE succeeded as part of a stacked query
  const hasInsert = statements.some((s) => /^INSERT\b/i.test(s.trim()));
  const hasDelete = statements.some((s) => /^DELETE\b/i.test(s.trim()));
  const insertSucceeded = hasInsert && allTablesAffected.length > 0 && !lastError;
  const dataModified = insertSucceeded || (hasDelete && allTablesAffected.length > 0);

  return {
    rows: lastRows,
    rowCount: lastRows.length,
    error: lastError,
    executedQuery: normalized,
    tablesAffected: allTablesAffected,
    dataExtracted,
    authBypassed,
    tableModified,
    dataModified,
    syntaxError: hadSyntaxError,
  };
}

// Reconstruct the vulnerable query from source code by substituting input
export function reconstructQuery(input: string, source: SourceFile): string | null {
  const content = source.content;

  // f-string: query = f"SELECT ... WHERE col = '{var}'"
  const fStringMatch = content.match(/f["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)\{(\w+)\}(['"]?.*?)["']/i);
  if (fStringMatch) {
    return `${fStringMatch[1]}${input}${fStringMatch[3]}`;
  }

  // f-string without quotes around variable: f"SELECT ... WHERE col = {var}"
  const fStringRawMatch = content.match(/f["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*)\{(\w+)\}(.*?["'])/i);
  if (fStringRawMatch) {
    return `${fStringRawMatch[1]}'${input}'${fStringRawMatch[3]}`;
  }

  // concatenation: "SELECT ... WHERE col = '" + var + "'"
  const concatMatch = content.match(/["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)["']\s*\+\s*(\w+)\s*\+\s*["'](.*)["']/i);
  if (concatMatch) {
    return `${concatMatch[1]}${input}${concatMatch[3]}`;
  }

  // concatenation without trailing quote: "SELECT ... WHERE col = '" + var
  const concatNoTrailingMatch = content.match(/["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)["']\s*\+\s*(\w+)/i);
  if (concatNoTrailingMatch) {
    return `${concatNoTrailingMatch[1]}${input}'`;
  }

  // .format(): "SELECT ... WHERE col = '{}'".format(var)
  const formatMatch = content.match(/["'](SELECT\s+.*?WHERE\s+\w+\s*=\s*['"]?\{\}['"]?.*?)["']\.format\s*\(\s*(\w+)\s*\)/i);
  if (formatMatch) {
    return `${formatMatch[1].replace('{}', input)}`;
  }

  // %-formatting: "SELECT ... WHERE col = '%s'" % var
  const percentMatch = content.match(/["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)%[sdr](.*?["'])\s*%\s*(\w+)/i);
  if (percentMatch) {
    return `${percentMatch[1]}${input}${percentMatch[2]}`;
  }

  // Variable-then-execute: query = f"SELECT ..." then cursor.execute(query)
  const queryAssignMatch = content.match(/(?:query|sql|stmt|q)\s*=\s*f["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)\{(\w+)\}(.*?["'])/i);
  if (queryAssignMatch) {
    return `${queryAssignMatch[1]}${input}${queryAssignMatch[3]}`;
  }

  // Variable-then-execute with concatenation: query = "SELECT ..." + var
  const queryConcatAssign = content.match(/(?:query|sql|stmt|q)\s*=\s*["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)["']\s*\+\s*(\w+)/i);
  if (queryConcatAssign) {
    return `${queryConcatAssign[1]}${input}'`;
  }

  // Variable-then-execute with %-format: query = "SELECT ... %s" % var
  const queryPercentAssign = content.match(/(?:query|sql|stmt|q)\s*=\s*["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)%[sdr](.*?["'])\s*%\s*(\w+)/i);
  if (queryPercentAssign) {
    return `${queryPercentAssign[1]}${input}${queryPercentAssign[2]}`;
  }

  // Variable-then-execute with .format: query = "SELECT ... {}".format(var)
  const queryFormatAssign = content.match(/(?:query|sql|stmt|q)\s*=\s*["'](SELECT\s+.*?WHERE\s+\w+\s*=\s*['"]?\{\}['"]?.*?)["']\.format\s*\(\s*(\w+)\s*\)/i);
  if (queryFormatAssign) {
    return `${queryFormatAssign[1].replace('{}', input)}`;
  }

  // Multi-line concatenation:
  // query = "SELECT * FROM users WHERE username = '" + username + "'"
  // spread across multiple lines
  const multilineConcat = content.match(/["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)["']\s*\+\s*\n?\s*(\w+)\s*\+\s*\n?\s*["']([^"']*)["']/is);
  if (multilineConcat) {
    return `${multilineConcat[1]}${input}${multilineConcat[3]}`;
  }

  // f-string multi-line:
  // query = f"SELECT * FROM users
  //          WHERE username = '{username}'"
  const multilineFString = content.match(/f["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"]?)\{(\w+)\}([^"']*?)["']/is);
  if (multilineFString) {
    return `${multilineFString[1]}${input}${multilineFString[3]}`.replace(/\n/g, ' ');
  }

  return null;
}

// Extract SQL context from the source — the WHERE clause structure
export function extractSQLContext(source: SourceFile): { context: string; sourceVar: string; sink: string; column: string; table: string } | null {
  const content = source.content;

  // Try to extract: SELECT ... FROM <table> WHERE <col> = '<var>'
  // from f-string, concat, format, percent patterns
  const patterns = [
    // f-string: f"SELECT ... FROM <table> WHERE <col> = '{var}'"
    /f["']SELECT\s+(?:.*?)\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*['"]?\{(\w+)\}['"]?/i,
    // concat: "SELECT ... FROM <table> WHERE <col> = '" + var
    /["']SELECT\s+(?:.*?)\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*['"]?["']\s*\+\s*(\w+)/i,
    // format: "SELECT ... FROM <table> WHERE <col> = '{}'".format(var)
    /["']SELECT\s+(?:.*?)\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*['"]?\{\}['"]?/i,
    // percent: "SELECT ... FROM <table> WHERE <col> = '%s'" % var
    /["']SELECT\s+(?:.*?)\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*['"]?%[sdr]/i,
  ];

  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match) {
      const table = match[1];
      const column = match[2];
      const sourceVar = match[3] || 'input';
      // Determine sink
      const sinkMatch = content.match(/\.execute\s*\(\s*(\w+)\s*\)/);
      const sink = sinkMatch ? `${sinkMatch[1]} → execute()` : 'execute()';
      return {
        context: `SELECT * FROM ${table} WHERE ${column} = '<INPUT>'`,
        sourceVar,
        sink,
        column,
        table,
      };
    }
  }

  return null;
}

// Reconstruct a SAFE (parameterized) query — input becomes a literal value
export function reconstructSafeQuery(input: string, source: SourceFile): string | null {
  const content = source.content;

  // Parameterized: query = "SELECT ... WHERE col = ?" then execute(query, (var,))
  const paramMatch = content.match(/["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*)\?["']/i);
  if (paramMatch) {
    return `${paramMatch[1]}'${input.replace(/'/g, "''")}'`;
  }

  // Named param: text("SELECT ... WHERE col = :name") with {"name": var}
  const namedMatch = content.match(/["'](SELECT\s+.*?FROM\s+\w+\s+WHERE\s+\w+\s*=\s*):(\w+)["']/i);
  if (namedMatch) {
    return `${namedMatch[1]}'${input.replace(/'/g, "''")}'`;
  }

  return null;
}
