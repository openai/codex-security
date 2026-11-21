import { fileURLToPath } from "node:url";
import { readSkillRuntimeInstructions } from "./skill_instructions.mjs";

const [topic, clientSurface] = process.argv.slice(2);
const pluginRoot = fileURLToPath(new URL("..", import.meta.url));
try {
  const text = await readSkillRuntimeInstructions(pluginRoot, topic, {
    clientSurface,
  });
  process.stdout.write(text);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
