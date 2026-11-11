import { parseArgs } from "node:util";

export function runXtask(): string {
  const { values } = parseArgs({ options: {} });
  return JSON.stringify(values);
}
