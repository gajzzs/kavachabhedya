import type { SourceFile } from '@/types';
import { generateId } from '@/lib/utils';

// ============================================================
// Source Ingestion Service
// Reads actual user-provided files via the File API.
// Files are treated as untrusted — content is read but NEVER
// executed during ingestion. No backend required: the browser
// File API gives us direct access to file contents.
// ============================================================

const EXTENSION_MAP: Record<string, string> = {
  py: 'python',
  js: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  java: 'java',
  go: 'go',
  php: 'php',
  c: 'c',
  cpp: 'cpp',
  cc: 'cpp',
  h: 'c',
  sql: 'sql',
};

const LANGUAGE_LABEL: Record<string, string> = {
  python: 'Python',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  java: 'Java',
  go: 'Go',
  php: 'PHP',
  c: 'C',
  cpp: 'C++',
  sql: 'SQL',
};

export const SUPPORTED_EXTENSIONS = Object.keys(EXTENSION_MAP);

export function isSupportedFile(filename: string): boolean {
  const ext = getExtension(filename);
  return ext in EXTENSION_MAP;
}

export function getExtension(filename: string): string {
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

export function detectLanguage(filename: string): string {
  const ext = getExtension(filename);
  const lang = EXTENSION_MAP[ext] || 'unknown';
  return LANGUAGE_LABEL[lang] || lang;
}

export function detectLanguageCode(filename: string): string {
  const ext = getExtension(filename);
  return EXTENSION_MAP[ext] || 'unknown';
}

export async function computeSHA256(text: string): Promise<string> {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'hash-unavailable';
  }
}

export interface IngestionResult {
  file: SourceFile;
  fileSize: number;
  extension: string;
  hash: string;
  language: string;
  languageCode: string;
  lineCount: number;
  preview: string;
}

export async function ingestFile(file: File): Promise<IngestionResult> {
  const content = await file.text();
  const extension = getExtension(file.name);

  if (!isSupportedFile(file.name)) {
    throw new Error(`Unsupported file type: .${extension}. Supported: ${SUPPORTED_EXTENSIONS.map((e) => '.' + e).join(', ')}`);
  }

  const languageCode = EXTENSION_MAP[extension] || 'unknown';
  const language = LANGUAGE_LABEL[languageCode] || languageCode;
  const lineCount = content.split('\n').length;
  const hash = await computeSHA256(content);
  const preview = content.substring(0, 2000);

  const sourceFile: SourceFile = {
    id: generateId('file'),
    filename: file.name,
    path: file.name,
    language: languageCode,
    content,
    lineCount,
  };

  return {
    file: sourceFile,
    fileSize: file.size,
    extension,
    hash,
    language,
    languageCode,
    lineCount,
    preview,
  };
}

export async function ingestRawCode(filename: string, content: string): Promise<IngestionResult> {
  const extension = getExtension(filename) || 'cpp';
  const languageCode = EXTENSION_MAP[extension] || 'cpp';
  const language = LANGUAGE_LABEL[languageCode] || languageCode;
  const lineCount = content.split('\n').length;
  const hash = await computeSHA256(content);
  const preview = content.substring(0, 2000);

  const sourceFile: SourceFile = {
    id: generateId('file'),
    filename,
    path: filename,
    language: languageCode,
    content,
    lineCount,
  };

  return {
    file: sourceFile,
    fileSize: new TextEncoder().encode(content).length,
    extension,
    hash,
    language,
    languageCode,
    lineCount,
    preview,
  };
}

