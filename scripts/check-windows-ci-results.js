"use strict";

// The stable windows-validation check must remain red when EITHER independent
// Windows job failed, was cancelled, was skipped or never produced a result.
function requireBothWindowsJobs(release, canonical) {
  if (release !== "success" || canonical !== "success") {
    throw new Error("Windows jobs not both successful");
  }
  return true;
}

function requireAllCanonicalShards(result) {
  if (result !== "success") throw new Error("Canonical shard matrix not successful");
  return true;
}

if (require.main === module) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 1 && args[0] === "--canonical-shards") {
      requireAllCanonicalShards(process.env.SHARDS_RESULT);
      console.log("PASS: both Windows canonical shards succeeded");
    } else if (args.length === 0) {
      requireBothWindowsJobs(process.env.RELEASE_RESULT, process.env.SUITE_RESULT);
      console.log("PASS: both independent Windows gates succeeded");
    } else {
      throw new Error("Invalid Windows gate mode");
    }
  } catch {
    // Do not echo arbitrary environment values into logs.
    console.error("FAIL: Windows jobs not both successful");
    process.exitCode = 1;
  }
}

module.exports = { requireBothWindowsJobs, requireAllCanonicalShards };
