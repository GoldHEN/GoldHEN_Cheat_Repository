# GoldHEN Cheat Database
_Cheat Menu allows you bring up a Menu while in-game for you to select cheats._

# Initial Cheats Credits
_Thanks to PS4Trainer For Initial Trainers Database and all Cheats Creators._

## Features
- `.json` support
- `.shn` support
- `.mc4` support

### :warning: Warnings
The Cheat Menu is experimental, use with caution.
At GoldHEN organization we don't develop cheats we only support compatible formats.
Please report cheat related issues to the cheat author(s) and/or go to https://github.com/GoldHEN/GoldHEN_Cheat_Repository/discussions/42 and follow instructions.

### Disclaimer:
While we make every effort to deliver high quality products, we do not guarantee that our products are free from defects. Our software is provided 'as is' and you use the software at your own risk.

### Usage:
- Long press `Share` button in-game to bring up Cheat menu or quick double PS button (depending on the trigger method you choose on GoldHEN settings).
- `↑` / `↓` to highlight cheat.
- `X` to Toggle cheat `On`/`Off`.

### Storage:
- Use `FTP` to upload cheat files to:
  - `/user/data/GoldHEN/cheats/json/`
  - `/user/data/GoldHEN/cheats/shn/`
  - `/user/data/GoldHEN/cheats/mc4/`
- Naming conversion for cheats that attach to eboot.bin process: `{titleid}_{version}.{format}`
  - e.g. `CUSA001234_01.01.json`
  - e.g. `CUSA001234_01.01.shn`
  - e.g. `CUSA001234_01.01.mc4`
- Naming conversion for cheats that attach to a non eboot.bin process (usually on collection games): `{titleid}_{version}_{process}.{format}`
  - e.g. `CUSA001234_01.01_example.elf.json`
  - e.g. `CUSA001234_01.01_example.elf.shn`
  - e.g. `CUSA001234_01.01_example.elf.mc4`
 - **Note:** Only one file format per `titleid` and `version` is currently supported.

### To Do:
- Add more cheat formats.

### Credits
- [ctn123](https://github.com/ctn123)
- [ShininGami](https://github.com/ScriptSK)
- [SiSTRo](https://github.com/SiSTR0)
