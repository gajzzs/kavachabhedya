# KAVACH — Robustness Upgrades

## What was changed

1. **Adversarial Security Benchmark**
   - New sidebar page: `Adversarial Benchmark`.
   - Tests vulnerable and secure source variants.
   - Reports TP/FP/TN/FN, precision, recall and F1.
   - Includes alias propagation, function propagation, formatting variants and safe controls.

2. **Fixed-point taint propagation**
   - Repeatedly propagates taint through assignment chains instead of checking only one hop.
   - Handles common indexed/container reads as additional propagation paths.

3. **Safer controlled SQL executor**
   - Unsupported `WHERE` expressions no longer silently return every row.
   - Unknown tables are treated as execution errors.
   - UNION payloads are checked against the actual table column count.

4. **Schema-aware fuzzing**
   - UNION mutations derive their arity from the extracted source schema.
   - INSERT mutations derive column names from the same schema when available.

5. **Patch verification improvement**
   - Verification checks whether the **original vulnerability class** remains after a patch.
   - Unrelated findings can be reported separately instead of automatically making the original fix look ineffective.

## How to use

```bash
npm install
npm run dev
```

Open the app and choose **Adversarial Benchmark** from the sidebar, then click **Run Benchmark**.

The benchmark is intentionally deterministic and uses the same analyzer/fuzzer code as the application. The numbers shown are calculated at runtime.

## Security scope

The current SQL DAST/fuzzer remains a controlled, isolated in-memory execution model. It is useful for detector validation and research demonstrations, but it is not equivalent to running an arbitrary uploaded application in a production-like sandbox.

The supplied `.env.example` is a template. Keep real environment values in your local `.env` and never commit service-role/private keys to a client-side `VITE_*` variable.
