# Security Toolkit (Firefox extension)

## After every build

Each time a new `.xpi` is built, also write these two texts and give them to the user in the chat, ready to paste into addons.mozilla.org (AMO):

1. **Release notes**: for users, in English, short bullets of what changed in this version.
2. **Notes for Mozilla reviewers**: for the AMO review team, in English. What changed in the code, why each permission and host is needed, that there is no build step or minified code (the package is the source), and how to test without API keys (Quick Scan only works offline) and with them.

## Releasing

- The version lives in `manifest.json` only; the popup and settings page read it from there.
- Build: zip `manifest.json`, all `*.js`, `*.css`, `*.html` and the `fonts`, `icons` and `img` folders into `security_toolkit-<version>.xpi`. Keep only the latest `.xpi` in the repository. `README.md`, `CLAUDE.md` and `.github` stay out of the package.
- Add the version to the changelog in `README.md`.
- Before building, check that the repository is not behind the latest version published on AMO. Versions 1.7.2 to 1.7.6 were published without being committed, and 1.7.7 was then built from older source and dropped their features.
