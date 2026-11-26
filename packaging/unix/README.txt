LocalTunnel V0.6 native agent development preview (unsigned)

Requires Python 3 for the installer and a trusted local filesystem. Obtain
install.py, the matching OS/architecture archive, and its expected SHA256
from a trusted channel. The checksums are not publisher signatures.

Run: python3 install.py PACKAGE.tar.gz EXPECTED_SHA256 /absolute/new-install-dir
Use a canonical absolute path under your own trusted directory. No sudo.
The installer rejects existing destinations, unexpected files and bad hashes.
It does not register services or write credentials.

Using the installed localtunnel-agent executable:
  agent-store-init /absolute/new-store
  agent-config-create /absolute/store SERVER:PORT NAME 127.0.0.1:PORT
    Supply token and server public key on two lines via protected stdin;
    do not put the token on the command line or in shell history.
  agent-engine-install /absolute/store /absolute/install-dir/rathole
  agent-config-check /absolute/store
  agent-run /absolute/store
  agent-service-generate /absolute/store 32_LOWERCASE_HEX_ID
The last command only generates an opt-in user service definition.
See docs/v0.6.md in the repository for explicit OS service commands.
Stop/unload services before deleting files. Removing the installation
directory is manual; keep or separately remove your private store as desired.
No signed installer, notarization, upgrade or rollback support in this preview.
