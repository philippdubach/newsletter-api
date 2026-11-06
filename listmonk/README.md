# Listmonk overrides

`static/` overlays the templates built into Listmonk 6.2.0 and is installed at
`/etc/listmonk/static` on the production host. `listmonk.service` loads it with
`--static-dir`. Files not listed here keep the built-in version.

Recheck these copies against upstream when upgrading Listmonk. `index.html` and
`optin.html` start from the upstream files. `optin.html` adds a redirect that
confirms in the browser, so the email button is the only click.
