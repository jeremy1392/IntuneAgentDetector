# Agent Detector: technical reference

This page explains how Agent Detector works. To deploy it, follow the
[README](../README.md).

- [What it detects](#what-it-detects)
- [How a scan works](#how-a-scan-works)
- [The disclaimer window](#the-disclaimer-window)
- [Branding file](#branding-file)
- [Approved tools](#approved-tools)
- [Tool ids](#tool-ids)
- [What the installation does](#what-the-installation-does)
- [Command line](#command-line)
- [Outputs](#outputs)
- [Intune Remediations script](#intune-remediations-script)
- [Troubleshooting](#troubleshooting)
- [Maintaining the catalog](#maintaining-the-catalog)
- [Privacy](#privacy)
- [Limitations](#limitations)
- [Development](#development)

## What it detects

**Known tools**, from the catalog in [rules/catalog.yaml](../rules/catalog.yaml):

| Category | Examples |
|---|---|
| CLI agents | Claude Code, OpenAI Codex, Gemini CLI, GitHub Copilot CLI, OpenCode, Aider, Goose, Open Interpreter |
| Desktop agents and assistants | Claude Desktop (incl. Cowork), ChatGPT Desktop |
| AI IDEs | Cursor, Windsurf, Kiro, Trae |
| IDE agents and assistants | GitHub Copilot, VS Code agent mode with MCP servers, Cline, Roo Code, Kilo Code, Continue, Amazon Q, Gemini Code Assist, Augment, Tabnine, Qodo, JetBrains AI / Junie |
| Local LLM runtimes | Ollama, LM Studio, Jan, GPT4All, AnythingLLM, llama.cpp / llamafile, Hugging Face local models |
| Agentic browsers and extensions | Perplexity Comet, AI browser extensions (Claude, ChatGPT, Perplexity, Monica, Sider…) |
| Gateways and frameworks | LiteLLM proxy, Browser Use, CrewAI, AutoGen, OpenAI Agents SDK, Claude Agent SDK… |

**Unknown agents**, without any signature. An agent can be 20 lines of Python,
so the scanner also looks for behavior:

| Signal | Finding |
|---|---|
| A process is connected to an LLM endpoint of the catalog: model providers, aggregators such as OpenRouter, inference platforms, gateways, known relays | `<provider> used by <process>` |
| That process also runs shells or interpreters (cmd, PowerShell, bash, git…) | `Probable custom AI agent (<process>)` |
| An `*_BASE_URL` / `*_API_BASE` variable points to a host outside the catalog | `Unknown LLM relay <host>` |
| A process loads inference DLLs (`ggml*`, `llama*`, `onnxruntime-genai`) | `Local LLM runtime in <process>` |
| An MCP server runs (`@modelcontextprotocol/…`, `mcp-server-*`, `uvx mcp-…`) | evidence on the agent that launched it, or `MCP server …` |
| A browser runs under automation (`--remote-debugging-port`, Playwright, Puppeteer) | evidence on the agent that drives it, or `Automated browser` |

**Past use**, between two scans: Windows execution traces (BAM and Prefetch)
and the modification date of agent history folders. File contents are never
read.

## How a scan works

One scan collects, in parallel and without any network request:

| Source | What it gives |
|---|---|
| Process snapshot | path, command line, owner, session, MSIX package, version info, Authenticode signer, loaded modules, LLM-related environment variables of candidate processes |
| TCP table + Windows DNS cache | which process talks to which LLM endpoint (the cache maps addresses back to host names) |
| BAM, Prefetch, history folders | recent use, including short-lived processes |
| Registry and known folders | MSIX packages, installed programs, services, IDE and browser extensions, global npm/pip packages, configuration folders, MCP configs, local models, API key variables (presence only) |

The correlator then builds **one finding per tool and per user**, graded by:

- **Level**: `active` (running or connected now) > `recent` (used in the last
  30 days, set with `--days`) > `installed` > `residue` (leftover data).
- **Confidence**: `high` (package, install path, command line or vendor
  signature), `medium` (executable name, behavior, configuration), `low`
  (circumstantial, for example a connection through a shared CDN address).
- **Approved**: the tool or endpoint is in the `sanctioned` list of the catalog.

A finding is **actionable** when it is not approved, at least installed, and of
medium or high confidence.

## The disclaimer window

Every scan that finds an agent (level active, recent or installed, confidence
medium or high) opens a window in that user's session:

- the company logo, then the heading;
- the detected tools, each marked "approved" or "not approved", followed by the
  disclaimer text, in a scrollable area;
- a checkbox and the only button, **I accept**, disabled until the box is
  ticked;
- a link to the AI policy and a clickable contact e-mail;
- no close button; the window stays on top of the others.

**The window comes back at every scan for as long as an agent is still
detected**, approved or not. Accepting it is logged (event 410) but does not
silence the next scan. With the default task, a user who keeps an agent sees it
at logon and every hour; change the frequency with `install.ps1
-IntervalMinutes`. Leftover data (level residue) and low-confidence findings
never open it.

The scan runs as SYSTEM in session 0, which cannot draw on a user's desktop. It
therefore relaunches its own executable in each active session, with the user's
token, and does not wait for the click. If a window is still open in a session,
the next scan does not open a second one. A user who is not signed in sees the
window at the first scan after sign-in. The window process writes event 410
under the user's identity when the user accepts.

The default text is a draft and must be validated by Legal and the DPO before
deployment.

## Branding file

Texts, company name, logo, AI policy and contact e-mail are set in
[branding/branding.yaml](../branding/branding.yaml). The build copies the
`branding` folder into the package, and `install.ps1` copies it to
`C:\Program Files\DetectorAgent\branding`, where only administrators can change
it. The program reads `branding\branding.yaml` next to itself, or the file given
with `--branding`.

| Field | Content |
|---|---|
| `version` | Number of the text; increase it at every change. Recorded in events 400 and 410 to prove which text a user accepted, and part of the Intune detection value. |
| `company` | Company name, used by the `{company}` placeholder. |
| `logo` | PNG (transparency supported) or JPEG shown at the top, 5 MB at most. Scaled down to fit 540 x 80 pixels, never enlarged. |
| `title`, `heading`, `text`, `checkbox`, `button` | The texts of the window. `text` is shown after the list of detected tools. |
| `policy`, `policy_label` | The AI policy link: an `https://` address, or a document placed in the branding folder (PDF, DOCX, DOC, PPTX, XLSX, ODT, RTF, HTML, TXT, MD). |
| `email`, `email_subject`, `contact_text` | Contact e-mail shown as a mailto link; `contact_text` must contain `{email}`. |

- Texts accept the `{company}` and `{email}` placeholders. For `logo`, `policy`
  and `email`, the value `none` removes the element.
- Unknown keys, invalid addresses, missing files and unsupported file types are
  rejected, so that a typo never deploys the default text silently. The build
  and `install.ps1` both refuse an invalid file.
- Check a file without showing anything:
  `.\dist\detectoragent.exe check-branding .\branding\branding.yaml`.
- A complete example for a fictitious company, logo included, is in
  [examples/branding-demo](../examples/branding-demo). It is for previews only:
  the build warns if `branding` holds it.

At run time, an invalid or missing branding file never blocks the disclaimer:
the default texts are shown and event 900 explains why. A logo that cannot be
read is skipped the same way.

## Approved tools

The `sanctioned` list in [rules/catalog.yaml](../rules/catalog.yaml) accepts:

- tool ids, such as `github-copilot` (see [Tool ids](#tool-ids));
- endpoint host names, such as `contoso.openai.azure.com`, which approve
  connections to that service, for example a script that calls your company's
  Azure OpenAI resource;
- endpoint suffixes starting with a dot, such as `.business.githubcopilot.com`.

An approved finding is still listed in the window, marked "approved". It is not
actionable: events 100 and 300 stay at the Information level, the scan exit
code does not count it, and the Intune Remediations report does not flag it.
The catalog is embedded in the program: rebuild after every change.

## Tool ids

| Id | Tool |
|---|---|
| `claude-code` | Claude Code |
| `openai-codex` | OpenAI Codex / ChatGPT app |
| `gemini-cli` | Gemini CLI |
| `github-copilot-cli` | GitHub Copilot CLI |
| `opencode` | OpenCode |
| `aider` | Aider |
| `goose` | Goose |
| `open-interpreter` | Open Interpreter |
| `claude-desktop` | Claude Desktop (incl. Cowork) |
| `chatgpt-desktop` | ChatGPT Classic desktop |
| `cursor` | Cursor |
| `windsurf` | Windsurf |
| `kiro` | Kiro |
| `trae` | Trae |
| `github-copilot` | GitHub Copilot (IDE) |
| `vscode-agent-mcp` | VS Code agent mode (MCP servers configured) |
| `cline` | Cline |
| `roo-code` | Roo Code |
| `kilo-code` | Kilo Code |
| `continue` | Continue |
| `gemini-code-assist` | Gemini Code Assist |
| `amazon-q` | Amazon Q Developer |
| `augment` | Augment Code |
| `tabnine` | Tabnine |
| `qodo` | Qodo Gen |
| `jetbrains-ai` | JetBrains AI Assistant / Junie |
| `perplexity-comet` | Perplexity Comet (agentic browser) |
| `browser-ai-extension` | AI browser extension |
| `ollama` | Ollama |
| `lm-studio` | LM Studio |
| `jan` | Jan |
| `gpt4all` | GPT4All |
| `anythingllm` | AnythingLLM |
| `llama-cpp` | llama.cpp / llamafile |
| `huggingface-models` | Hugging Face local models |
| `litellm` | LiteLLM proxy |
| `browser-use` | Browser Use |
| `agent-frameworks` | AI agent framework (Python) |
| `agent-sdks-node` | AI agent SDK (Node.js, global) |

## What the installation does

Intune runs `install.ps1` as SYSTEM. The script:

1. restarts itself in 64-bit PowerShell when it starts as a 32-bit process, as
   Intune starts `powershell.exe`;
2. checks that it runs elevated, removes the install marker, and stops any
   running `detectoragent.exe`;
3. copies `detectoragent.exe` to `C:\Program Files\DetectorAgent`;
4. replaces `C:\Program Files\DetectorAgent\branding` with the package's
   `branding` folder, and refuses an invalid branding file;
5. recreates `C:\ProgramData\DetectorAgent`, where the scan writes
   `last-scan.json`, with SYSTEM and Administrators as the only writers.
   Standard users can create folders under ProgramData, so an existing folder
   is never trusted;
6. registers the `DetectorAgent` source of the Application event log;
7. creates the scheduled task `\DetectorAgent\DetectorAgent Scan`, run as
   SYSTEM, with the command
   `detectoragent.exe scan --out C:\ProgramData\DetectorAgent\last-scan.json`,
   plus `--no-disclaimer` in silent mode. It runs at every logon after 2
   minutes, and every day from midnight, repeated every `-IntervalMinutes`.
   Only one instance runs at a time, for 10 minutes at most, on battery too,
   and a missed scan runs as soon as the PC wakes up;
8. writes the install marker `HKLM\SOFTWARE\DetectorAgent` last: `Package`,
   read by the Intune detection rule, then `Version`, `BrandingVersion`,
   `Mode`, `IntervalMinutes` and `InstalledAt`.

`Package` is `<file version>-b<branding version>-<mode>`, for example
`1.0.0.0-b1-disclaimer`. Changing the program version, the branding `version`
or the mode changes it, so Intune installs again.

The script logs to
`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DetectorAgent-install.log`
and exits with 0 when installed, 1 when it failed.

| Parameter | Default | Meaning |
|---|---|---|
| `-NoDisclaimer` | off | Silent mode: scan and log, never show the window |
| `-IntervalMinutes` | 60 | Scan interval, 15 to 1440 minutes |
| `-Source`, `-BrandingDir` | next to the script | Files to install |
| `-InstallDir` | `C:\Program Files\DetectorAgent` | Install folder |
| `-DataDir` | `C:\ProgramData\DetectorAgent` | Report folder |

`uninstall.ps1` removes the task, stops the program, and deletes the marker, the
install folder, the report folder and the Event Log source. Events already
written stay in the log.

## Command line

```
detectoragent scan [--format json|text] [--out FILE] [--rules FILE] [--branding FILE]
                   [--days N] [--no-disclaimer] [--no-eventlog] [--timeout 60s]
detectoragent disclaimer --preview [--branding FILE]   # show the window with sample tools, record nothing
detectoragent disclaimer --selftest [--branding FILE]  # show it and accept it after 2 s, record nothing
detectoragent check-branding [FILE]                    # validate a branding file, show nothing
detectoragent version
```

| Exit code | Meaning |
|---|---|
| 0 | no actionable finding |
| 1 | at least one unapproved AI tool detected |
| 2 | error, or incomplete scan (see `errors`) with nothing detected |
| 3 | disclaimer not accepted (disclaimer command) |

Run it elevated for full coverage. Without administrator rights it scans only
the current user and cannot read BAM, Prefetch or the DNS cache; the report
lists these gaps in `coverage_notes`.

## Outputs

**JSON report**: product and catalog versions, host, account, duration,
coverage notes, summary counters, and the findings with their evidence. Command
lines are included for investigation, masked and truncated. The scheduled task
writes it to `C:\ProgramData\DetectorAgent\last-scan.json`.

**Windows Event Log** (Application log, source `DetectorAgent`). Each message
is a JSON document.

| Event ID | Level | Content |
|---|---|---|
| 100 | Information, Warning if actionable | scan summary and compact list of all findings |
| 300 | Information, Warning if actionable | one finding with its evidence (installed or above, medium or high confidence) |
| 400 | Information | disclaimer shown to a user |
| 410 | Information | disclaimer accepted; written under the user's identity, so the event carries the user's SID |
| 900 | Error | scanner or disclaimer error |

To collect the events in Microsoft Sentinel, add the Application log to a data
collection rule with this XPath query:
`Application!*[System[Provider[@Name='DetectorAgent']]]`.

Suggested SIEM rules: dashboard of findings by tool, category and user; alert on
actionable findings; alert when a PC sends no event 100 for more than 24 hours.

## Intune Remediations script

`intune-detect.ps1` is a detection-only Remediations script. It runs its own
scan as SYSTEM, with no window and no Event Log entry, so it never doubles the
events of the scheduled task. It prints one line, which Intune shows as the
detection output, for example
`Unapproved AI tools: Claude Code (active); OpenAI Codex / ChatGPT app (active)`.
Intune keeps 2,048 characters of output; the script cuts the line at 2,000.

The script exits with 1, which Intune reports as **With issues**, only when an
unapproved tool is at least installed and detected with medium or high
confidence. Every other path, errors included, exits with 0 and a line that
says why, so a script failure never flags a PC.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Install fails, and `DetectorAgent-install.log` has no entry for that attempt | The PCs enforce AllSigned: the scripts are unsigned, or their certificate is not a Trusted Publisher | Sign the package (README, section 4) and deploy the certificate to Trusted Publishers before the app |
| The Trusted Publishers profile reports error -2016281112 | The Base64 value contains line breaks or spaces | Paste the one-line output of the command in the README, section 4 |
| Install fails; the log says `Invalid branding file` | A key, an address or a file in `branding.yaml` is wrong | Run `.\dist\detectoragent.exe check-branding .\branding\branding.yaml`, fix `branding`, rebuild |
| Install fails; the log says `must run elevated` | Install behavior is set to User | Set Install behavior to System |
| Intune reports the app as not detected after a successful install | The rule's value differs from the marker, or the 32-bit option is Yes | Compare the rule with `Package` under `HKLM\SOFTWARE\DetectorAgent`; set the 32-bit option to No |
| An update has not reached a PC | The PC has not checked in yet, or the detection value was not changed | Restart the PC or wait for the hourly check-in; make sure the rule holds the new value printed by `build.ps1` |
| A failed install is not retried at once | Intune offers a required app again about once a day | Fix the cause, then restart the PC or wait |
| The app reinstalls again and again | Two apps with different detection values target the same PC | Keep one Agent Detector app per PC |
| Users never see the window | Silent install (`Mode` is `silent`), or only leftovers and low-confidence findings | Check `Mode` in the marker and the findings in `last-scan.json` |
| `.\build.ps1` cannot be loaded because running scripts is disabled | The workstation's execution policy blocks scripts | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first |
| The build stops with `signing ... failed` | Your workstation does not trust the certificate chain | Trust the issuing CA's root certificate, or use a certificate from a trusted CA |
| The build stops with `cannot empty dist\` | A preview window or another program uses `dist` | Close it and build again |

## Maintaining the catalog

- Edit [rules/catalog.yaml](../rules/catalog.yaml), test with
  `scan --rules FILE`, then rebuild: the catalog is embedded in the executable.
- Review the catalog monthly. Sources: vendor network allow-lists, LiteLLM's
  provider list, the "Generative AI" category of Defender for Cloud Apps, and
  the `Unknown LLM relay` findings reported by the fleet.
- Endpoints and identifiers were checked against vendor documentation and DNS
  on 2026-11-08. What is still marked `unverified` (the Anthropic address range
  and a few install paths) needs confirmation on a real installation. Lambda's
  and OpenPipe's API hosts were removed: they no longer exist.

## Privacy

- Never collected: prompt or conversation content, file contents, API key
  values.
- Command lines and messages are masked (`sk-…`, `sk-ant-…`, `AIza…`, `ghp_…`,
  `--api-key …`, `*_KEY=…`, URL credentials) before they leave the process.
- Of a base URL, only the host name is kept.
- In France, deploy only after updating the IT charter, informing and consulting
  the CSE, and recording the processing (RGPD register and DPIA). The disclaimer
  tells users that detections and acceptances are logged.

## Limitations

- Not continuous: an agent started and stopped between two scans is only seen
  through its traces, and a script run by `python.exe` only leaves
  `python.exe`.
- The DNS cache keeps names for a few minutes and needs administrator rights on
  recent Windows builds (the scheduled task runs as SYSTEM).
- Agents running fully in the cloud, in a VM, in WSL or in a container, and
  relays on arbitrary domains, are out of reach of the endpoint: cover them with
  the web proxy (TLS inspection) and Defender for Cloud Apps.
- Signatures are parsed but not cryptographically verified, to keep the scan
  fast; MSIX apps are identified by their package family name instead.
- A local administrator can remove the task: alert on missing event 100.

## Development

```
main.go                      CLI: scan, disclaimer, check-branding, version
build.ps1                    tests, build, signing, Intune packaging
rules/catalog.yaml           embedded catalog (default disclaimer, generic patterns, tools, endpoints)
branding/                    disclaimer customization, copied into the package by the build
examples/branding-demo/      fictitious branding for previews
internal/catalog             catalog loading, matchers, branding loading and validation
internal/scan                collectors (processes, network, DNS cache, traces, inventory, environment)
internal/correlate           findings, levels, confidence, generic agent rules
internal/disclaimer          pending tools, session launch, Win32 window, logo rendering
internal/report              JSON, text and Event Log output
internal/redact              secret masking
scripts/                     install, uninstall, Intune detection
winres/                      manifest, icon and version resource (go-winres)
docs/                        this reference and the README screenshot
```

`go test ./...` runs the unit tests. They cover catalog matching, correlation on
a synthetic snapshot (known agent, unknown agent, relay, local LLM, MCP, browser
automation, sanctioned endpoints), the disclaimer trigger rules (shown again at
every scan), payload and window content, branding loading and validation, logo
scaling and transparency, parsing helpers and secret masking.
