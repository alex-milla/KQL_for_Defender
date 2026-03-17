
# GlassWorm — Wave 5: New Delivery Techniques Targeting MCP, GitHub & VSCode

> **Threat Intelligence:** [Lotan Sery](https://lnkd.in/dN9Md5cD) — [koi.ai](https://www.koi.ai)  
> **Original research:** [GlassWorm Hits MCP: 5th Wave with New Delivery Techniques](https://www.koi.ai/blog/glassworm-hits-mcp-5th-wave-with-new-delivery-techniques) — March 16, 2026  
> **KQL Detection Rules:** [Alex Millà - alexmilla.dev]

---

## Summary

GlassWorm is a persistent supply chain threat actor first identified in October 2025, known for using **invisible Unicode characters** to hide malicious payloads inside VSCode extensions. Wave 5, identified on **March 12–16, 2026**, represents their largest operation to date and introduces their **first confirmed compromise of an MCP (Model Context Protocol) server** via a malicious npm package.

Key developments in this wave:
- **150+ GitHub repositories** compromised with AI-generated camouflage commits (March 3–9, 2026)
- **72+ malicious VSCode/OpenVSX extensions** leveraging transitive dependency abuse
- **First MCP server compromise** published to npm under a fake `@iflow-mcp` scope
- Decryption keys moved out of extension code into HTTP response headers — defeating static analysis
- Continued use of **Solana blockchain memos** as C2 dead drops
- RC4 obfuscation replacing the previous AES loader

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Indicator | Type | Description |
|---|---|---|
| `45.32.150.251` | IP Address | C2 server — persistent across waves |
| `45.32.151.157` | IP Address | C2 server — persistent across waves |
| `70.34.242.255` | IP Address | C2 server — Wave 5 |

---

### Blockchain Indicators (Solana — C2 Dead Drop)

| Indicator | Type | Description |
|---|---|---|
| `6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ` | Solana Address | Active C2 wallet — Wave 5 |
| `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` | Solana Address | C2 wallet — Wave 4, still active |

---

### Malicious npm Packages

| Package | Version | Description |
|---|---|---|
| `@iflow-mcp/watercrawl-watercrawl-mcp` | All versions (1.3.0–1.3.4) | Fake MCP server — trojanized clone of legitimate `watercrawl-mcp` |
| `@aifabrix/miso-client` | 4.7.2 | Malicious npm package |

---

### Attacker Infrastructure (GitHub)

| Indicator | Type | Description |
|---|---|---|
| `github.com/iflow-mcp/watercrawl-watercrawl-mcp` | Repository | Attacker fork used for MCP supply chain attack |
| `iflow` | Branch name | Malicious branch containing the injected payload |

---

### Compromised GitHub Repositories (Victims)

| Repository | Notes |
|---|---|
| `pedronauck/reworm` | 1,460 stars — high-profile compromise |
| `anomalyco/opencode-bench` | Organization behind OpenCode and SST |
| `wasmer-examples/hono-wasmer-starter` | Wasmer starter template |

> ⚠️ Over 150 repositories were compromised between March 3–9, 2026. The above are confirmed high-profile examples. Full list not yet published.

---

### Malicious VSCode Extensions

| Extension ID | Marketplace |
|---|---|
| `quartz.quartz-markdown-editor` (0.3.0) | VS Code Marketplace |
| `aadarkcode.one-dark-material` | OpenVSX |
| `aligntool.extension-align-professional-tool` | OpenVSX |
| `angular-studio.ng-angular-extension` | OpenVSX |
| `awesome-codebase.codebase-dart-pro` | OpenVSX |
| `awesomeco.wonder-for-vscode-icons` | OpenVSX |
| `bhbpbarn.vsce-python-indent-extension` | OpenVSX |
| `blockstoks.easily-gitignore-manage` | OpenVSX |
| `brategmaqendaalar-studio.pro-prettyxml-formatter` | OpenVSX |
| `codbroks.compile-runnner-extension` | OpenVSX |
| `codevunmis.csv-sql-tsv-rainbow` | OpenVSX |
| `codwayexten.code-way-extension` | OpenVSX |
| `cosmic-themes.sql-formatter` | OpenVSX |
| `craz2team.vscode-todo-extension` | OpenVSX |
| `crotoapp.vscode-xml-extension` | OpenVSX |
| `cudra-production.vsce-prettier-pro` | OpenVSX |
| `daeumer-web.es-linter-for-vs-code` | OpenVSX |
| `dark-code-studio.flutter-extension` | OpenVSX |
| `densy-little-studio.wonder-for-vscode-icons` | OpenVSX |
| `dep-labs-studio.dep-proffesinal-extension` | OpenVSX |
| `dev-studio-sense.php-comp-tools-vscode` | OpenVSX |
| `devmidu-studio.svg-better-extension` | OpenVSX |
| `dopbop-studio.vscode-tailwindcss-extension-toolkit` | OpenVSX |
| `errlenscre.error-lens-finder-ex` | OpenVSX |
| `exss-studio.yaml-professional-extension` | OpenVSX |
| `federicanc.dotenv-syntax-highlighting` | OpenVSX |
| `flutxvs.vscode-kuberntes-extension` | OpenVSX |
| `gvotcha.claude-code-extension` | OpenVSX |
| `gvotcha.claude-code-extensions` | OpenVSX |
| `intellipro.extension-json-intelligence` | OpenVSX |
| `kharizma.vscode-extension-wakatime` | OpenVSX |
| `ko-zu-gun-studio.synchronization-settings-vscode` | OpenVSX |
| `kwitch-studio.auto-run-command-extension` | OpenVSX |
| `lavender-studio.theme-lavender-dreams` | OpenVSX |
| `littensy-studio.magical-icons` | OpenVSX |
| `lyu-wen-studio-web-han.better-formatter-vscode` | OpenVSX |
| `markvalid.vscode-mdvalidator-extension` | OpenVSX |
| `mecreation-studio.pyrefly-pro-extension` | OpenVSX |
| `mswincx.antigravity-cockpit` | OpenVSX |
| `mswincx.antigravity-cockpit-extension` | OpenVSX |
| `namopins.prettier-pro-vscode-extension` | OpenVSX |
| `oigotm.my-command-palette-extension` | OpenVSX |
| `otoboss.autoimport-extension` | OpenVSX |
| `ovixcode.vscode-better-comments` | OpenVSX |
| `pessa07tm.my-js-ts-auto-commands` | OpenVSX |
| `potstok.dotnet-runtime-extension` | OpenVSX |
| `pretty-studio-advisor.prettyxml-formatter` | OpenVSX |
| `prismapp.prisma-vs-code-extension` | OpenVSX |
| `projmanager.your-project-manager-extension` | OpenVSX |
| `pubruncode.ccoderunner` | OpenVSX |
| `pyflowpyr.py-flowpyright-extension` | OpenVSX |
| `pyscopexte.pyscope-extension` | OpenVSX |
| `redcapcollective.vscode-quarkus-elite-suite` | OpenVSX |
| `rubyideext.ruby-ide-extension` | OpenVSX |
| `runnerpost.runner-your-code` | OpenVSX |
| `shinypy.shiny-extension-for-vscode` | OpenVSX |
| `sol-studio.solidity-extension` | OpenVSX |
| `ssgwysc.volar-vscode` | OpenVSX |
| `studio-jjalaire-team.professional-quarto-extension` | OpenVSX |
| `studio-velte-distributor.pro-svelte-extension` | OpenVSX |
| `sun-shine-studio.shiny-extension-for-vscode` | OpenVSX |
| `sxatvo.jinja-extension` | OpenVSX |
| `tamokill12.foundry-pdf-extension` | OpenVSX |
| `thing-mn.your-flow-extension-for-icons` | OpenVSX |
| `tima-web-wang.shell-check-utils` | OpenVSX |
| `tokcodes.import-cost-extension` | OpenVSX |
| `toowespace.worksets-extension` | OpenVSX |
| `treedotree.tree-do-todoextension` | OpenVSX |
| `tucyzirille-studio.angular-pro-tools-extension` | OpenVSX |
| `turbobase.sql-turbo-tool` | OpenVSX |
| `twilkbilk.color-highlight-css` | OpenVSX |
| `vce-brendan-studio-eich.js-debuger-vscode` | OpenVSX |
| `yamaprolas.revature-labs-extension` | OpenVSX |

---

## Campaign History

| Wave | Date | Key Technique |
|---|---|---|
| Wave 1 | Oct 2025 | Invisible Unicode in OpenVSX, Solana + Google Calendar C2 |
| Wave 2 | Nov 2025 | More extensions; attacker server accessed; Russian-speaking actor confirmed |
| Wave 3 | Nov 2025 | Rust binaries; expanded to official VS Code Marketplace |
| Wave 4 | Dec 2025 | macOS pivot; encrypted JS payloads; hardware wallet trojanization; 50K downloads |
| **Wave 5** | **Mar 2026** | **150+ GitHub repos; 72+ extensions; first MCP compromise; AI-generated commits; RC4; keys in HTTP headers** |

---

## References

- Lotan Sery / koi.ai — [GlassWorm Hits MCP: 5th Wave with New Delivery Techniques](https://www.koi.ai/blog/glassworm-hits-mcp-5th-wave-with-new-delivery-techniques) (March 16, 2026)
- Aikido Security — Independent tracking of GlassWorm Wave 5
- Socket — Independent tracking of GlassWorm Wave 5

---

## Disclaimer

All threat intelligence and IOCs in this repository are sourced from **koi.ai** research. This repository provides **KQL detection rules** for Microsoft Sentinel based on that research. Use for defensive purposes only.
