# Gwennyfer: a Discord bot for BIOS analysis

Gwennyfer is a Discord bot that answers questions through an AI model and comes with a set of
tools for firmware work. Attach a BIOS image, an update program or a diskette image and ask
about it: the bot identifies the BIOS, unpacks its modules and rebuilds its **setup screens**
as they look on a real PC, with the ROM's own default values.

Most setup screens are rebuilt by running the BIOS itself. An x86 emulator built on
[Unicorn](https://www.unicorn-engine.org/) runs the POST of the emulated board up to the setup
prompt, presses the keys a person would press and reads back each page. Firmware that cannot
run this way is read from the image: Award screen scripts, AMIBIOS 8 page scripts, Phoenix
templates and UEFI HII forms. Downloaded files are only ever read as data. Their code runs only
inside the emulator, never on the host.

The same tools are also available without Discord, as an [MCP server](#mcp-server) for any MCP
client.

## Features

- `/ask` (or an @mention or DM): ask the AI a question, optionally with up to five attached
  files (ten with a mention). It reads them with file tools: text in windows, PDFs page by
  page, images directly.
- **Reply to an answer** to ask a follow-up question; the answer you reply to is passed along
  as context. Otherwise every question stands on its own.
- Files are kept per user and per channel. Nobody can read, overwrite or delete another user's
  files. `/reset` deletes your own files; old files are pruned by age and size.
- Uploaded files are parsed in a separate process per question, with a time limit and, on
  Windows, memory and process limits, so a damaged or hostile file cannot take the bot down.
  On Windows that process runs at low integrity: it can write only to the work folder, which
  the bot labels for it on first use (granting its own user full control there if needed).
- `/ping` shows the latency.
- Web search and page fetching through a [SearXNG](https://docs.searxng.org/) instance, with
  Ollama's web API as an optional fallback. Only public addresses are fetched, and the
  connection goes to the address that was checked. Answers are sent without link previews.
- Limits on concurrent questions and on questions per user per hour.

## BIOS analysis tools

| Tool | What it does |
| --- | --- |
| `bios_summary` | One-call overview: vendor, version, BIOS ID, date, chipset, Super I/O, CPU and board hints, setup page titles; packed images are searched decompressed. |
| `rom_info` | Checksum, entropy layout, option ROMs with PCI IDs, signatures, reset vector, BIOS date. |
| `unpack_rom` | Module lists and contents: Award LHA modules, AMIBIOS 95/98/8, PhoenixBIOS 4.0/6.0 BCPSYS. |
| `bios_setup_screens` | Rebuilds the setup screens as PNG pages (and as text for the AI), with a contact sheet of all pages. |
| `vbe_modes` | VESA modes of a video BIOS. |
| `disassemble` | Capstone disassembly: x86 16/32/64, 6502/65816, 68000, 6809, ARM, MIPS, PPC. |
| `hexdump`, `strings`, `search_bytes`, `file_hashes` | The basics, each bounded so its result fits the model's context. |
| `render_text_screen` | Lets the AI draw an 80x25 VGA text screen of its own. |

### Containers and update programs

Update programs are opened as data, never run. The bot reads:
- ZIP and LHA archives, and self-extracting updates that carry them;
- 7z, RAR and CAB, if [7-Zip](https://www.7-zip.org/) is installed;
- FAT12/16 diskette images;
- Inno Setup installers holding a bootable CD image;
- Disk eXPress (DXP) and Sydex SXD diskettes;
- Compaq/HP Softpaq ROMPaq;
- LZEXE-packed DOS programs;
- MSI's SQX archives;
- Fujitsu-Siemens .BUP/.OCF/.OMF;
- Intel's split updates (.BIO/.BI1/..., recovery sets, Express BIOS Update) and EFI updates;
- images behind a header, or as two EPROM halves (EVEN/ODD) that are interleaved.

### Supported BIOS types for setup screens

Rebuilt from the image (no emulation):

- **Award Modular 4.5x** (e.g. 4.51PG), by interpreting Award's screen-script byte code.
- **Award 6.00PG** full flash images. This includes the Phoenix-AwardBIOS menu-bar setup (e.g.
  ASUS A7N8X), Gigabyte's variants, and OEM main menus built by code.
- **Award Medallion 6.0** (e.g. ASUS A7V8X-X).
- **AMIBIOS 8** on chipsets the emulator does not model (VIA, SiS, NVIDIA): page scripts,
  language module and default CMOS image.
- **Intel desktop-board BIOS** (AMI core 6.32, about 1999-2003), when its POST does not run.
- **PhoenixBIOS 4.0** templates read from the image, and **Phoenix TrustedCore / SecureCore**.
- **UEFI** (AMI Aptio 4/5 and other firmware with HII forms, also the older Framework HII).
  The pages are drawn as text, or in the vendor's own look for ASUS, ASRock, Gigabyte, MSI,
  EVGA and Sapphire.

Run in the emulator (POST, then the setup):

- **Classic AMIBIOS** (about 1988-1994), AMI's 286 BIOS with built-in diagnostics, and AMI
  WinBIOS (1994-97, the graphical setup).
- **AMIBIOS Simple/Hi-Flex** and **Easy Setup**, **AMIBIOS 7** (the new setup utility and the
  tabbed 3.31a setup), and **AMIBIOS 8** on Intel chipsets (845-875).
- **Intel's own desktop-board BIOS** and **Intel Express BIOS** (1995-97, including Dell's
  Dimension variant).
- **Early Award Modular** (v3.x-4.50, 286/386/486 boards).
- **PhoenixBIOS before 4.0** (ROM BIOS PLUS, Phoenix SETUP Utility), **early PhoenixBIOS 4.0x**
  (NuBIOS, DragonBIOS and OEM setups) and **PhoenixBIOS 4.0 Release 6** (the graphical setup).
- **MR BIOS** (Microid Research).
- **Dell's** Phoenix ROM BIOS PLUS 1.10 setup (Dimension, OptiPlex, about 2003-04).
- The vendors' own BIOSes of **Acer**, **Chips and Technologies** (SCAT), **DTK**, **Mylex**,
  **NCR**, **Novell** ATterminal, **Quadtel**, **Tandon** and **Texas Micro**.
- Simple one-screen setups offered at a POST error.

The emulator models what these BIOSes need from a PC of their time:
- the PIT, PIC, 8042 keyboard controller, DMA, CMOS/RTC and a floppy controller;
- a PCI bus with Intel (430/440/8xx with ICH), VIA, SiS, ALi, UMC and AMD host and ISA
  bridges, including their shadow-RAM registers;
- SMBus with SPD EEPROMs;
- VGA text and 16-colour graphics, read back as text with the setup's own font.

Recognised but not rebuilt: XT-class BIOSes, Compaq (setup not in the ROM), coreboot, U-Boot
and the NeXT ROM Monitor. Values on the pages are the defaults stored in the ROM; a real PC
shows what its CMOS holds.

## Installation

Requirements: Python 3.14, a Discord application, and an AI server that speaks the Anthropic
Messages API. 7-Zip is optional, for 7z, RAR and CAB containers.

1. Create an application at <https://discord.com/developers/applications>.
   1. Under **Bot**, reset the token and save it in `discord-token.txt` next to `bot.py`.
   2. Enable **Message Content Intent** (Bot → Privileged Gateway Intents) for @mentions and
      DMs.
2. Invite the bot with OAuth2 → URL Generator, using the scopes `bot` and
   `applications.commands`. For DMs and Group DMs, also enable **User Install** under
   Installation and add the app to your account.
3. Install:

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   copy .env.example .env
   ```

4. Configure the bot:
   1. In `.env`, set `AI_BASE_URL` and `AI_MODEL` for your AI server, and `SEARXNG_URL` if you
      have SearXNG.
   2. Put the AI server's API key in `api-key.txt`, and optionally an Ollama API key in
      `ollama-api-key.txt`.

   The three key files are git-ignored.
5. Start the bot:

   ```powershell
   python bot.py
   ```

   Slash commands are synced globally on startup and may take a few minutes to appear.

### Settings (`.env`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `AI_BASE_URL`, `AI_MODEL`, `AI_MAX_TOKENS` | | The AI server and model. |
| `MAX_TOOL_ROUNDS` | 40 | Rounds of tool calls per question. |
| `MAX_CONCURRENT_QUESTIONS`, `QUESTIONS_PER_HOUR` | | Load limits. |
| `MAX_MESSAGES`, `MESSAGE_DELAY` | 5, 1.5 | How long answers are split into messages. |
| `SEARXNG_URL`, `BOT_WEB` | | Web search: `auto`, `searxng`, `ollama` or `none`. |
| `WORK_DIR`, `FILE_MAX_DAYS`, `USER_MAX_BYTES`, `WORK_MAX_BYTES` | | Where attachments are kept and for how long. |
| `BOT_NICKNAME` | | Nickname the bot sets in each server. |

## MCP server

`mcp_server.py` offers the file and BIOS tools over stdio to any MCP client, without Discord or
an AI server.
- **Files.** All files are read from and written to one folder: `MCP_WORK_DIR`, by default
  `mcp-work/`.
- **Isolation.** Each call runs in a process of its own with a time limit (`MCP_CALL_SECONDS`).
- **Long jobs.** Rebuilding setup screens can take minutes, so it runs as a job: start it with
  `start_setup_screens` and fetch the pages with `job_result`.

```json
{ "mcpServers": { "bios-tools": { "command": "python", "args": ["mcp_server.py"],
  "env": { "MCP_WORK_DIR": "C:/bios" } } } }
```

## Licence

MIT, see [LICENSE](LICENSE). The AMI and Phoenix module readers are written from the image
formats. `tiano.py` follows the decompressor of EDK2 (BSD-2-Clause-Patent; its notice is in
[NOTICE](NOTICE)), and `sqx.py` the format description of Squeez-c (MIT). The bot depends on Unicorn
(GPL-2.0), Capstone (BSD), discord.py (MIT), Pillow (MIT-CMU) and pypdfium2
(Apache-2.0/BSD). They are installed separately, not part of this repository.
