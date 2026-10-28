"use strict";

// The stable windows-validation check must remain red when EITHER independent
// Windows job failed, was cancelled, was skipped or never produced a result.
function requireBothWindowsJobs(release, canonical) {
  if (release !== "success" || canonical !== "success") {
    throw new Error("Windows jobs not both successful");
  }
  return true;
}

if (require.main === module) {
  try {
    requireBothWindowsJobs(process.env.RELEASE_RESULT, process.env.SUITE_RESULT);
    console.log("PASS: both independent Windows gates succeeded");
  } catch {
    // Do not echo arbitrary environment values into logs.
    console.error("FAIL: Windows jobs not both successful");
    process.exitCode = 1;
  }
}

module.exports = { requireBothWindowsJobs };
