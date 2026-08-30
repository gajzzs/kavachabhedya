import { runSAST } from './src/services/security-tools/sastAnalyzer';
import { demoProjects } from './src/services/demoProjects';

const project = demoProjects[0];
console.log('Project:', project.name);
const result = runSAST(project.files);
console.log('Findings:', result.findings.length);
for (const f of result.findings) {
  console.log('  -', f.vulnerabilityClass, 'at', f.file + ':' + f.line, 'confidence:', f.confidence, 'authenticity:', f.authenticity);
  console.log('    evidence:', f.evidence);
}
