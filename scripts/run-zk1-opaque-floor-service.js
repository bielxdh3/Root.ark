"use strict";

// NODE_ENV=development node scripts/run-zk1-opaque-floor-service.js CONFIG
const { startZk1OpaqueCatalogIndependentFloorServiceFromConfig } =
  require("../src/services/zk1OpaqueCatalogIndependentFloorService");
if (process.argv.length !== 3) {
  process.stderr.write("ZK_OPAQUE_FLOOR_SERVICE_CONFIG_DENIED\n");
  process.exitCode = 1;
} else {
  startZk1OpaqueCatalogIndependentFloorServiceFromConfig(process.argv[2]).then((running) => {
    const stop = () => running.close().then(() => {
      process.exitCode = 0;
    }).catch(() => { process.exitCode = 1; });
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  }).catch(() => {
    process.stderr.write("ZK_OPAQUE_FLOOR_SERVICE_UNAVAILABLE\n");
    process.exitCode = 1;
  });
}
