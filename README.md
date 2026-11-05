# spoof-discord-badges (vanta rebuild)

per-badge custom targets for discord profile badges — game hours, games played, streaming hours.

posts the same events the real discord client posts to `/api/v9/science`:
- `launch_game` + `running_game_heartbeat` for game hours and games played
- stream events for streaming hours (speculative path, see below)

## status

game hours and games-played paths are confirmed working (source-verified against the original tool).
streaming-hours path is **speculative** — the event shape is invented, not documented, and the
streaming badge is probably fed by gateway voice events rather than `/science`. expect it to do
nothing. badges update on discord's analytics cycle, 1–2 days.

this breaks discord's tos. use it on accounts you're fine losing.

## setup

pure python 3.10+, no dependencies.

    python spoofer.py

first run walks you through token + `cf_clearance` cookie. both saved to `science_state.json`.
fingerprint generation is menu option 4 (windows only) — generates a real `executable_fingerprint`
tied to your machine + account for the games-played badge.

## menu

- `1` · game hours — total hours target, distributed realistically across games
- `2` · games played — target count, 1 min each, uses fingerprint
- `3` · streaming hours — target hours (speculative path)
- `4` · set fingerprint — generate a real `executable_fingerprint`
- `5` · refresh auth — re-mint analytics token, optionally update cookie
- `6` · exit

## custom hours override

drop `custom_hours.json` next to `spoofer.py` to control per-game hours:

    { "1091500": 4.5, "271590": 12.0, "730": 2.0 }

keys are discord game ids, values are hours. when present, menu option 1 uses this instead of
distributing a total.

## verification

every batch is logged to `science_state.json` under `event_log` — timestamp, status, game count,
game ids. after 1–2 days, cross-reference which games actually credited. 204 means accepted,
not recorded.

## license

mit. original by revere group. rebuild keeps the dolfies fingerprint generator (mit) verbatim.