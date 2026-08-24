# HuntQuery

**HuntQuery** is a local, rule-based browser tool that accepts supported plain-language hunting requests or existing query syntax and translates them into query/filter syntax for common network-security tools. It does not use AI or an LLM.

> Example: `show DNS traffic from 10.0.0.5 to 8.8.8.8 in the last 24 hours`

HuntQuery can generate output for one tool, several tools, or all supported targets at once. It can also auto-detect supported syntax pasted from one tool and translate the recognized fields into another.

## Try it online

**Live demo:** [Open HuntQuery](https://vanessamporter.github.io/HuntQuery/)

HuntQuery runs entirely in your browser and makes no application network requests. You can also download the project and use it fully offline.

## Supported targets

- **Arkime** — session and PCAP hunting expressions
- **Malcolm DQL** — OpenSearch Dashboards DQL-style searches
- **Malcolm Lucene** — Lucene-style Malcolm/OpenSearch searches
- **Splunk SPL** — network searches using CIM-style field mappings
- **Wireshark** — display filters
- **Zeek** — `jq` filters for Zeek JSON logs
- **Suricata** — `jq` filters for Suricata EVE JSON
- **Security Onion** — Hunt/Dashboards-style filtering

## Features

- Plain-language input for common network-hunting concepts
- Query-to-query translation with auto-detection for supported syntax
- Compact multi-select target menu
- Generate queries for multiple tools at the same time
- Clickable examples that populate the input for quick experimentation
- Per-query **Copy** buttons plus **Copy all**
- Fast input clearing with the inline **Clear** control or `Esc`
- Validation for malformed IPv4/CIDR values, invalid ports, invalid HTTP status codes, oversized input, and unsafe control characters
- Time phrases such as `last 24 hours` are kept separate from query syntax when the target normally uses a UI time picker
- Warnings for unsupported or ambiguous translations instead of silently inventing fields
- Dark navy and gold interface
- Runs locally with no backend and no application network requests

## Run HuntQuery

No build process or package installation is required.

### Recommended

From the project directory, start HuntQuery with Node.js:

```bash
npm start
```

Then open `http://127.0.0.1:3000` in your browser.

No Python, backend framework, or external npm package is required. You can also open `index.html` directly, although serving it locally provides more consistent browser behavior.

## Example workflow

1. Enter a plain-language request or paste supported query syntax, for example:

   ```text
   show DNS traffic from 10.0.0.5 to 8.8.8.8
   ```

   or:

   ```text
   ip.src == 10.0.0.5 && protocols == dns
   ```

2. Open **Target tools** and select one or more destinations, such as Arkime and Wireshark.
3. Generate the translation.
4. Review the generated syntax and any warnings.
5. Copy an individual result or use **Copy all**.

## Security design

HuntQuery is intentionally a static client-side application. It has no database, authentication system, server-side API, file upload handler, or backend command execution.

The current build includes several defensive controls:

- restrictive Content Security Policy (CSP)
- `connect-src 'none'`
- no user-controlled `innerHTML`
- no `eval` or `new Function`
- text-only DOM APIs for user-controlled values
- 4,096-character input limit
- rejection of unsafe control characters
- shell-safe quoting for generated Zeek and Suricata `jq` commands

These controls reduce the attack surface but do not guarantee that the application is free of every vulnerability. Always review generated queries before using them in a production environment.

## Automated tests

HuntQuery uses Node's built-in test runner and has no npm package dependencies.

Requirements: **Node.js 18+**

Run:

```bash
npm test
```

or:

```bash
node --test tests/tests.js
```

The regression and security suite covers input validation, query generation across supported targets, multi-target behavior, CIDR edge cases, shell-command quoting, CSP checks, and common DOM-XSS sink checks.

## Important limitations

- **Splunk:** field names vary between deployments. HuntQuery uses common/CIM-style mappings, so generated SPL may require adjustment for your environment.
- **Zeek and Suricata:** these modes generate `jq` filters against JSON logs; they are not native Zeek or Suricata query languages.
- **CIDR with Zeek/Suricata `jq`:** plain `jq` does not provide reliable IP subnet-membership testing, so unsupported CIDR constraints are omitted with a warning rather than translated incorrectly.
- **Security Onion:** deployments can use customized field mappings.
- Natural-language translation is deterministic and intentionally limited to supported concepts; unsupported requests should produce warnings rather than fabricated syntax.

## Project structure

```text
HuntQuery/
├── index.html
├── app.js
├── translator-core.js
├── package.json
├── server.js
├── LICENSE
├── README.md
└── tests/
    └── tests.js
```

## Contributing

Issues and pull requests are welcome. If you add a new query target, field mapping, or parser behavior, add regression tests for both valid and invalid inputs.

## Disclaimer

Generated queries should be reviewed and validated before use in production environments.

## License

HuntQuery is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. See [LICENSE](LICENSE).
