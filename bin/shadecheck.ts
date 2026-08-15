#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { analyzeAddress, analyzeUri } from "../lib/analyzer";
import { exitCodeForGate, renderJson, renderText } from "../lib/cli";

type Mode = "auto" | "uri" | "address";

interface Options {
  mode: Mode;
  json: boolean;
  file: string | null;
  input: string | null;
  help: boolean;
}

function usage(): string {
  return [
    "Usage: npm run shadecheck -- [options] [input]",
    "",
    "Options:",
    "  --mode uri|address  Choose the parser explicitly (default: auto).",
    "  --file path         Read the request from a UTF-8 file.",
    "  --json              Print a machine-readable result.",
    "  --help              Show this help.",
    "",
    "Exit codes: 0 pass, 1 block, 2 review, 64 usage or input error.",
  ].join("\n");
}

function parseArgs(argv: string[]): Options {
  const options: Options = { mode: "auto", json: false, file: null, input: null, help: false };
  const positional: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") options.help = true;
    else if (argument === "--json") options.json = true;
    else if (argument === "--mode") {
      const mode = argv[index + 1];
      if (mode !== "auto" && mode !== "uri" && mode !== "address") throw new Error("--mode must be auto, uri, or address.");
      options.mode = mode;
      index += 1;
    } else if (argument === "--file") {
      options.file = argv[index + 1] ?? null;
      if (!options.file) throw new Error("--file needs a path.");
      index += 1;
    } else if (argument.startsWith("-")) throw new Error(`Unknown option: ${argument}`);
    else positional.push(argument);
  }
  if (positional.length > 1) throw new Error("Provide one input value, or use --file.");
  options.input = positional[0] ?? null;
  if (options.file && options.input) throw new Error("Use either an input value or --file, not both.");
  return options;
}

async function readInput(options: Options): Promise<string> {
  if (options.file) return (await readFile(options.file, "utf8")).trim();
  if (options.input) return options.input.trim();
  if (process.stdin.isTTY) throw new Error("No input provided. Pass an input, --file, or pipe a request on stdin.");
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function main(): Promise<void> {
  let options: Options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`ShadeCheck: ${error instanceof Error ? error.message : "Invalid arguments."}`);
    console.error(usage());
    process.exitCode = 64;
    return;
  }
  if (options.help) {
    console.log(usage());
    return;
  }

  try {
    const input = await readInput(options);
    if (!input) throw new Error("The input is empty.");
    const mode = options.mode === "auto" ? (/^zcash:/i.test(input) ? "uri" : "address") : options.mode;
    const analysis = mode === "uri" ? analyzeUri(input) : analyzeAddress(input);
    console.log(options.json ? renderJson(analysis) : renderText(analysis));
    process.exitCode = exitCodeForGate(analysis.gate);
  } catch (error) {
    console.error(`ShadeCheck: ${error instanceof Error ? error.message : "Unable to analyze input."}`);
    process.exitCode = 64;
  }
}

void main();
