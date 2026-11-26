import { spawn } from "node:child_process";
import { once } from "node:events";
import { connect, createServer } from "node:net";

const [binary, url, ...options] = process.argv.slice(2);
const port = Number(new URL(url).port || 80);

// Forward bytes unchanged. The suite generates the same loopback Host that it
// would send when testing a server on its own machine.
const relay = createServer((client) => {
  const target = connect(port, "target");
  client.on("error", () => target.destroy());
  target.on("error", () => client.destroy());
  client.pipe(target).pipe(client);
});

try {
  await once(relay.listen(port, "127.0.0.1"), "listening");
  const suite = spawn(binary, ["server", "--url", url, "--output-dir", "/tmp/results", ...options], {
    stdio: "inherit",
  });
  const [code] = await once(suite, "exit");
  process.exitCode = code ?? 2;
} finally {
  relay.close();
}
