// Where one distro's run writes its artefacts.
//
// Six containers share this directory through a single /project bind mount, and
// Playwright clears outputDir when it starts. An un-namespaced path therefore
// loses screenshots twice over: the next container deletes the previous one's
// before writing its own, and the collector then copies whatever survived over
// the top of the last distro's files. A full six-distro run left 37 screenshots
// on disk, all of them rhel's, while the summary reported six passes.
//
// Required by playwright.config.js and by tests/helpers.js, which are loaded by
// different mechanisms and must not disagree about the path.
const distro = process.env.HARDENER_DISTRO || 'local';

module.exports = {
  distro,
  outputDir: `test-results/${distro}`,
  // Outside outputDir on purpose: Playwright clears outputDir at startup, so a
  // report written into it does not survive the run that produced it.
  jsonReport: `test-reports/${distro}.json`,
};
