# Walkthrough: from a suspicious email to shareable evidence

This walkthrough follows one harmless sample through a typical triage: look at
the file, collect indicators, decode a hidden value, write a report, preserve
the result, compare it with a related sample and share the observables. Every
command runs offline. Outputs are shortened with `…`.

## The sample

Save this as `invoice.eml`. It imitates a common invoice lure: the sender
domain uses a Cyrillic `а` (U+0430) in place of the Latin `a`, replies go to a
different domain, and a "backup reference" hides a download URL in Base32. All
names are fictional (`example.*`), and nothing in it is executable.

```text
From: "Accounts Payable" <billing@exаmple.com>
Reply-To: payments@mailbox.example.org
To: analyst@example.com
Subject: Overdue invoice 4471
Date: Fri, 16 Oct 2026 09:12:44 +0000
Message-ID: <4471@exаmple.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello,

Invoice 4471 is overdue. Please review it today:
https://portal.exаmple.com/invoices/4471

If the portal does not open, use the backup reference below.
ref=NB2HI4DTHIXS6ZTJNRSXGLTFPBQW24DMMUXG4ZLUF5UW45TPNFRWKLJUGQ3TCLT2NFYA====

Accounts Payable
```

Copy it exactly: the lookalike `а` is what the later steps detect.

## 1. Look at the file

```text
$ banshee file inspect invoice.eml
Format: Email message
…
from: "Accounts Payable" <billing@exаmple.com>
reply-to: payments@mailbox.example.org
…
External link: https://portal.exаmple.com/invoices/4471
Finding: Email reply-to domain (mailbox.example.org) differs from the From domain (exаmple.com)
```

`file inspect` recognizes the format from its content, not its extension, and
lists headers, MIME parts, attachments and links. The Reply-To mismatch is the
first signal: answers would go to someone other than the apparent sender.

## 2. Collect indicators

```text
$ banshee extract --defang --domain --file invoice.eml
domain	example[.]com	count=1	lines=3-3	…
domain	mailbox[.]example[.]org	count=1	lines=2-2	…
domain	portal[.]xn--exmple-4nf[.]com	count=1	lines=13-13	…	note=possible homoglyph: portal.exаmple.com reads as portal.example.com and mixes Latin and Cyrillic letters
domain	xn--exmple-4nf[.]com	count=2	lines=1-6	…	note=possible homoglyph: exаmple.com reads as example.com and mixes Latin and Cyrillic letters
```

Internationalized domains are recorded in Punycode (`xn--exmple-4nf.com`),
the form that DNS, proxies and blocklists use, and the note explains why the
name is suspicious. `--defang` makes the output safe to paste into tickets and
chat. Drop `--domain` to see URLs and email addresses too, or add
`--format json` for scripts.

## 3. Decode the hidden value

```text
$ banshee whatis NB2HI4DTHIXS6ZTJNRSXGLTFPBQW24DMMUXG4ZLUF5UW45TPNFRWKLJUGQ3TCLT2NFYA====
Layers:
  [1] Base32 (99% confidence)
      -> https://files.example.net/invoice-4471.zip
…
Findings:
  - URL: https://files.example.net/invoice-4471.zip
```

`whatis` peels nested Base64, Base32, hex, URL, HTML, Unicode, gzip and zlib
layers, recovers simple XOR inside Base64 or hex, and explains each step. You rarely need to run it by hand:
`report`, `analyze` and `scan` decode tokens such as `ref=…` automatically and
add the decoded indicators to their results.

## 4. Write a report

```text
$ banshee report invoice.eml --builtin-rules --format markdown --output report.md
```

The report combines hashes (MD5, SHA-1, SHA-256, ssdeep, TLSH), file
structure, entropy, decoded content, IOCs and rule matches. In this sample
the findings include:

```text
- medium — file inspection: Email reply-to domain (mailbox.example.org) differs from the From domain (exаmple.com)
- medium — IOC extraction / domain: xn--exmple-4nf.com — possible homoglyph: exаmple.com reads as example.com …
- info — IOC extraction / url: https://files.example.net/invoice-4471.zip — decoded from Base32 …
```

`--builtin-rules` applies the starter rule pack compiled into Banshee
(`banshee rules builtin --list`); use `--rules my-rules.toml` for your own.
Other formats are `text`, `json`, `html` (a self-contained page with no
scripts) and `sarif`.

## 5. Preserve the result

```text
$ banshee --output case-4471 evidence create invoice.eml --builtin-rules
Created evidence bundle: case-4471
Files: 7
Findings: 15
Source sample included: false

$ banshee evidence verify case-4471
Valid: true
Entries checked: 6
```

The bundle holds the JSON and Markdown reports, hashes, IOCs, rule results
and a SHA-256 manifest. The sample itself is left out unless you pass
`--include-sample`, and secrets stay redacted. `evidence verify` detects any
changed, missing or added file later.

## 6. Compare with a related sample

A second email, `invoice-4472.eml`, uses invoice 4472 and a different
Reply-To mailbox:

```text
$ banshee --output case-4472 evidence create invoice-4472.eml --builtin-rules
$ banshee diff case-4471 case-4472
…
ssdeep similarity: 79/100
TLSH distance: 102 (0 = identical)
IOCs: left=available; right=available; +2 -2 ~0
  + {"kind":"email",…,"value":"billing-desk@mailbox.example.org"}
  + {"kind":"url",…,"value":"https://portal.xn--exmple-4nf.com/invoices/4472"}
  - {"kind":"email",…,"value":"payments@mailbox.example.org"}
  - {"kind":"url",…,"value":"https://portal.xn--exmple-4nf.com/invoices/4471"}
```

`diff` compares saved reports or verified bundles without touching the
original files. The fuzzy hashes show the two emails are close variants, and
the IOC changes show what the sender changed between them. The exit status is
1 when differences exist, which suits scripts.

## 7. Share observables

```text
$ banshee export case-4471 --format stix --output observables.stix.json
$ banshee export case-4471 --format misp --output event.misp.json
$ banshee export case-4471 --format csv
```

Exports contain observables (hashes, domains, URLs, emails, IPs) and never
verdicts or secret values. STIX 2.1 and MISP event JSON import into threat
intelligence platforms; CSV suits spreadsheets and SIEM lookups.

## Where to go next

- [Command examples](../examples/usage.md) for every command.
- `banshee` with no arguments opens the interactive console; `open
  invoice.eml` keeps the file open so `report`, `whatis @` and others work on
  it directly.
- Windows event logs (`.evtx`) work the same way: `file inspect Security.evtx`
  lists event IDs, providers, the time range and log-clearing events, and
  `report` extracts indicators from the event data.
