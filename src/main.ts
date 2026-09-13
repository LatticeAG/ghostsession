#!/usr/bin/env node
import { runCli } from "./cli.js";

runCli(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`fatal: ${(e as Error).message}\n`);
    process.exit(1);
  },
);
