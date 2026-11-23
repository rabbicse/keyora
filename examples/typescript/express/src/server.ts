import { createApp } from "./app.js";
import { loadConfig, type Config } from "./config.js";

let config: Config;
try {
  config = loadConfig();
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}

const server = createApp(config).listen(config.port, () => {
  console.log(`notes API listening on :${config.port} (Keyora at ${config.keyoraUrl})`);
});

server.on("error", (err) => {
  console.error(`could not listen on port ${config.port}: ${err.message}`);
  process.exit(1);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
