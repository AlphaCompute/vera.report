# Third-party notices

VERA is released under the MIT License (see `LICENSE`). It depends on
third-party packages under their own licenses. `package-lock.json` records the
declared license of almost every package. The exceptions are `busboy` 1.6.0 and
`streamsearch` 1.1.0, which declare MIT in the legacy `licenses` field that the
lockfile does not copy; each package ships its own `LICENSE` file.

Two runtime dependencies are licensed under the GNU Lesser General Public
License v3.0 or later (LGPL-3.0-or-later). They are used unmodified, as
separate libraries, and are not relicensed by this project.

| Component | Version | License | How VERA uses it |
| --- | --- | --- | --- |
| [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) (`openpgp`) | 6.3.2 | LGPL-3.0-or-later | Direct npm dependency, loaded as an unmodified module. |
| [libvips](https://github.com/libvips/libvips), via the prebuilt `@img/sharp-libvips-*` packages | 1.3.4 | LGPL-3.0-or-later | Shared library loaded at runtime by [`sharp`](https://github.com/lovell/sharp) 0.35.5 (Apache-2.0). Only the package matching the host platform is installed. |

The full license texts are in `licenses/LGPL-3.0.txt` and, because the LGPL
supplements the GPL, `licenses/GPL-3.0.txt`. The backend and frontend container
images include both files and this notice under `/app/licenses/`. OpenPGP.js
also ships its own copy as `node_modules/openpgp/LICENSE`. The `@img/sharp-libvips-*`
packages list their components' licenses in their README but don't include the
LGPL text.

Corresponding source code:

- OpenPGP.js: <https://github.com/openpgpjs/openpgpjs/tree/v6.3.2>
- libvips build used by sharp: <https://github.com/lovell/sharp-libvips/tree/v1.3.4>

You may replace either library with a modified version. Install your build in
place of the npm package (for libvips, see sharp's documentation on using a
globally installed libvips). Container images built from the `Dockerfile` install
these packages from npm unmodified.
