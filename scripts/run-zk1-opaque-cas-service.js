"use strict";

// Operator executable: NODE_ENV=development node scripts/run-zk1-opaque-cas-service.js CONFIG
// Requires explicit config, separately provisioned Ed25519 and mTLS credentials.
const { startZk1OpaqueCatalogCasServiceFromConfig } =
  require("../src/services/zk1OpaqueCatalogCasService");
if (process.argv.length !== 3) {
  process.stderr.write("ZK_OPAQUE_CAS_SERVICE_CONFIG_DENIED\n");
  process.exitCode = 1;
} else {
  startZk1OpaqueCatalogCasServiceFromConfig(process.argv[2]).then((running) => {
    const stop = () => running.close().then(() => {
      process.exitCode = 0;
    }).catch(() => {
      process.exitCode = 1;
    });
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  }).catch(() => {
    process.stderr.write("ZK_OPAQUE_CAS_SERVICE_UNAVAILABLE\n");
    process.exitCode = 1;
  });
}
