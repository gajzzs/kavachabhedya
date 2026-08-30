import { runAdversarialBenchmark } from './src/services/benchmarkService';

const report = runAdversarialBenchmark();
console.log(JSON.stringify({
  total: report.total,
  truePositives: report.truePositives,
  falsePositives: report.falsePositives,
  trueNegatives: report.trueNegatives,
  falseNegatives: report.falseNegatives,
  precision: report.precision,
  recall: report.recall,
  f1: report.f1,
}, null, 2));

if (report.falseNegatives > 0 || report.falsePositives > 0) {
  console.error('Benchmark found detector gaps. Review the case-by-case report.');
  process.exitCode = 1;
}
