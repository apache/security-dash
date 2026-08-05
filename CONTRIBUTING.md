To run the dashboard locally:

- Copy `config.yaml.example` to `config.yaml`
- run `python3 server.py`

# Authorization

There is an example config for testing against https://mfa-dev.apache.org .

If you want to test with different authorizations than your own, you can either patch the code accordingly or start a local oauth server (e.g. [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server), `JSON_CONFIG_PATH=./mock-oauth2-server-config.json nix run git+https://codeberg.org/raboof/mock-oauth2-server?ref=nix --no-write-lock-file`)
