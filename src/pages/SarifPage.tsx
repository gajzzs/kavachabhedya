import { useState, useCallback } from 'react';
import {
  FileSearch,
  Upload,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Filter,
  FileJson,
  Info,
} from 'lucide-react';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { AuthenticityBadge, SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { parseSARIF, getDemoSARIFJSON, createDemoSARIFReport } from '@/services/sarifService';
import type { SARIFReport, SARIFFinding } from '@/types';

export function SarifPage() {
  const [report, setReport] = useState<SARIFReport | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<SARIFFinding | null>(null);
  const [filter, setFilter] = useState<'ALL' | 'CORRECT_FINDING' | 'FALSE_POSITIVE' | 'UNCERTAIN'>('ALL');
  const [inputText, setInputText] = useState('');
  const [fileName, setFileName] = useState('');

  const handleParse = useCallback(async (source: string, content: string) => {
    setIsParsing(true);
    setReport(null);
    setSelectedFinding(null);
    await new Promise((r) => setTimeout(r, 1000));
    const result = parseSARIF({ source, content });
    setReport(result);
    setIsParsing(false);
  }, []);

  const handleFileUpload = useCallback(async (file: File) => {
    setFileName(file.name);
    const text = await file.text();
    setInputText(text);
    await handleParse(file.name, text);
  }, [handleParse]);

  const handleLoadDemo = useCallback(async () => {
    const demoJson = getDemoSARIFJSON();
    setFileName('demo-sarif-report.sarif');
    setInputText(demoJson);
    await handleParse('demo-sarif-report.sarif', demoJson);
  }, [handleParse]);

  const handleParseInput = useCallback(async () => {
    if (inputText.trim()) {
      await handleParse(fileName || 'manual-input.sarif', inputText);
    }
  }, [inputText, fileName, handleParse]);

  const filteredFindings = report?.findings.filter(
    f => filter === 'ALL' || f.validationDecision === filter
  ) || [];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">SARIF Analysis</h2>
          <p className="text-sm text-kavach-text-secondary">
            Import SARIF-format security reports. Kavach extracts findings, assesses reachability, and classifies them as correct, false positive, or uncertain.
          </p>
        </div>
        <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />
      </div>

      {/* Upload */}
      <Card>
        <CardHeader title="SARIF Import" subtitle="Upload a SARIF JSON file or use the demo report" icon={<Upload className="w-4 h-4" />} />
        <CardBody>
          <div className="space-y-4">
            <div className="flex flex-wrap gap-3">
              <label className="flex items-center gap-2 px-4 py-2 rounded-md bg-kavach-accent/10 text-kavach-accent border border-kavach-accent/30 hover:bg-kavach-accent/20 transition-all cursor-pointer">
                <Upload className="w-4 h-4" />
                <span className="text-sm font-medium">Upload SARIF File</span>
                <input
                  type="file"
                  accept=".sarif,.json"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleFileUpload(file);
                  }}
                />
              </label>
              <button
                onClick={handleLoadDemo}
                className="flex items-center gap-2 px-4 py-2 rounded-md bg-kavach-surface-2 text-kavach-text-secondary border border-kavach-border hover:border-kavach-accent/20 transition-all"
              >
                <FileJson className="w-4 h-4" />
                <span className="text-sm font-medium">Load Demo SARIF</span>
              </button>
            </div>

            {fileName && (
              <p className="text-xs text-kavach-text-muted">
                File: <code className="text-kavach-accent">{fileName}</code>
              </p>
            )}

            <div>
              <label className="kavach-section-title mb-2 block">Or paste SARIF JSON directly</label>
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                rows={4}
                placeholder='{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [...]}'
                className="w-full bg-kavach-bg border border-kavach-border rounded-md p-3 text-xs font-mono text-kavach-text-primary focus:border-kavach-accent focus:outline-none resize-y"
              />
            </div>

            <button
              onClick={handleParseInput}
              disabled={isParsing || !inputText.trim()}
              className="flex items-center gap-2 px-4 py-2 rounded-md bg-kavach-accent/10 text-kavach-accent border border-kavach-accent/30 hover:bg-kavach-accent/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isParsing ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileSearch className="w-4 h-4" />}
              <span className="text-sm font-medium">{isParsing ? 'Analyzing...' : 'Analyze SARIF'}</span>
            </button>
          </div>
        </CardBody>
      </Card>

      {/* Processing Flow */}
      <Card>
        <CardHeader title="SARIF Processing Pipeline" subtitle="From raw report to classified findings" icon={<Filter className="w-4 h-4" />} />
        <CardBody>
          <div className="flex items-center gap-1 flex-wrap text-xs">
            {['SARIF Report', 'Finding Extraction', 'Code Context', 'Reachability Analysis', 'PoC / Patch Matching', 'LLM Validation', 'Classification'].map((step, i, arr) => (
              <div key={step} className="flex items-center gap-1">
                <div className="px-3 py-1.5 rounded-md border border-kavach-border bg-kavach-surface-2 text-kavach-text-secondary font-mono">
                  {step}
                </div>
                {i < arr.length - 1 && <span className="text-kavach-text-muted">→</span>}
              </div>
            ))}
          </div>
          <p className="text-xs text-kavach-text-muted mt-3">
            SARIF parsing is IMPLEMENTED for basic JSON structure. Reachability analysis and validation are CONTROLLED DEMONSTRATION — derived from rule patterns and code context heuristics.
            Future integration: CodeQL / Semgrep / other SARIF-producing tools.
          </p>
        </CardBody>
      </Card>

      {/* Summary */}
      {report && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <SummaryCard label="Total Findings" value={report.totalFindings} icon={<FileSearch className="w-4 h-4" />} />
          <SummaryCard label="Correct Findings" value={report.correctFindings} icon={<CheckCircle2 className="w-4 h-4" />} color="success" />
          <SummaryCard label="False Positives" value={report.falsePositives} icon={<XCircle className="w-4 h-4" />} color="danger" />
          <SummaryCard label="Uncertain" value={report.uncertain} icon={<AlertCircle className="w-4 h-4" />} color="warning" />
        </div>
      )}

      {/* Filter + Findings */}
      {report && (
        <>
          <div className="flex items-center gap-2">
            <span className="text-xs text-kavach-text-muted">Filter:</span>
            {(['ALL', 'CORRECT_FINDING', 'FALSE_POSITIVE', 'UNCERTAIN'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 rounded text-xs font-medium border transition-all ${
                  filter === f
                    ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                    : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                }`}
              >
                {f.replace(/_/g, ' ')}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Findings List */}
            <Card>
              <CardHeader title="Extracted Findings" subtitle={`${filteredFindings.length} finding(s)`} icon={<FileSearch className="w-4 h-4" />} />
              <CardBody>
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {filteredFindings.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className={`w-full text-left p-3 rounded-md border transition-all ${
                        selectedFinding?.id === f.id
                          ? 'bg-kavach-accent/10 border-kavach-accent/30'
                          : 'bg-kavach-surface-2 border-kavach-border hover:border-kavach-accent/20'
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <SeverityBadge severity={f.severity} />
                        <code className="text-xs text-kavach-text-secondary flex-1 truncate">{f.ruleId}</code>
                      </div>
                      <p className="text-xs text-kavach-text-muted truncate">{f.file}:{f.line}</p>
                      <div className="flex items-center gap-2 mt-1">
                        <StatusBadge status={f.reachability} />
                        <ValidationBadge decision={f.validationDecision} />
                      </div>
                    </button>
                  ))}
                </div>
              </CardBody>
            </Card>

            {/* Finding Detail */}
            <Card>
              <CardHeader title="Finding Detail" subtitle="Reachability and validation analysis" icon={<Info className="w-4 h-4" />} />
              <CardBody>
                {selectedFinding ? (
                  <div className="space-y-3">
                    <div>
                      <p className="kavach-section-title mb-1">Rule</p>
                      <code className="text-sm text-kavach-accent">{selectedFinding.ruleId}</code>
                    </div>
                    <div>
                      <p className="kavach-section-title mb-1">Description</p>
                      <p className="text-sm text-kavach-text-secondary">{selectedFinding.description}</p>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <p className="kavach-section-title mb-1">Location</p>
                        <p className="text-sm text-kavach-text-secondary font-mono">{selectedFinding.file}:{selectedFinding.line}</p>
                      </div>
                      <div>
                        <p className="kavach-section-title mb-1">Severity</p>
                        <SeverityBadge severity={selectedFinding.severity} />
                      </div>
                    </div>
                    <div>
                      <p className="kavach-section-title mb-1">Reachability</p>
                      <div className="flex items-center gap-2">
                        <StatusBadge status={selectedFinding.reachability} />
                        <span className="text-xs text-kavach-text-muted">
                          {selectedFinding.reachability === 'REACHABLE' && 'Vulnerable code path is reachable from external input.'}
                          {selectedFinding.reachability === 'NOT_REACHABLE' && 'Code is not reachable from production paths.'}
                          {selectedFinding.reachability === 'UNCERTAIN' && 'Reachability cannot be determined from SARIF metadata alone.'}
                        </span>
                      </div>
                    </div>
                    <div>
                      <p className="kavach-section-title mb-1">Evidence</p>
                      <p className="text-sm text-kavach-text-secondary">{selectedFinding.evidence}</p>
                    </div>
                    <div>
                      <p className="kavach-section-title mb-1">Validation Decision</p>
                      <div className="flex items-center gap-2 mb-1">
                        <ValidationBadge decision={selectedFinding.validationDecision} />
                      </div>
                      <p className="text-xs text-kavach-text-muted">{selectedFinding.validationReason}</p>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center py-8">
                    <Info className="w-8 h-8 text-kavach-text-muted mb-2" />
                    <p className="text-sm text-kavach-text-muted">Select a finding to see detailed analysis.</p>
                  </div>
                )}
              </CardBody>
            </Card>
          </div>
        </>
      )}

      {/* Future Integration */}
      <Card>
        <CardBody>
          <div className="flex items-start gap-3">
            <Info className="w-4 h-4 text-kavach-accent flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-xs text-kavach-accent font-medium mb-1">Future Integration</p>
              <p className="text-xs text-kavach-text-muted">
                Kavach accepts external SARIF-compatible input. Future versions will integrate with CodeQL, Semgrep, and other SARIF-producing security tools
                to provide real scanner results with reachability analysis and automated PoC/patch matching.
              </p>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function SummaryCard({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color?: 'success' | 'danger' | 'warning' }) {
  const colorClass = color === 'success' ? 'text-kavach-success' : color === 'danger' ? 'text-red-400' : color === 'warning' ? 'text-amber-400' : 'text-kavach-text-primary';
  return (
    <Card hover>
      <CardBody>
        <div className="flex items-center justify-between mb-2">
          <span className={colorClass}>{icon}</span>
          <span className="text-[10px] font-mono text-kavach-text-muted uppercase">{label}</span>
        </div>
        <p className={`text-2xl font-bold ${colorClass}`}>{value}</p>
      </CardBody>
    </Card>
  );
}

function ValidationBadge({ decision }: { decision: 'CORRECT_FINDING' | 'FALSE_POSITIVE' | 'UNCERTAIN' }) {
  const styles: Record<string, string> = {
    CORRECT_FINDING: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    FALSE_POSITIVE: 'bg-red-500/10 border-red-500/30 text-red-400',
    UNCERTAIN: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  };
  return (
    <span className={`kavach-badge ${styles[decision]}`}>
      {decision.replace(/_/g, ' ')}
    </span>
  );
}
