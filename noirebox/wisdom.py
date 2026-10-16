"""The wall Randal asked for.

"Level 0 -> Level 1 -> Level 2 sentence deserves to be framed on the wall."
— Randal Schwartz, Part 3.8 comments. This is the frame.

Hidden command: `noirebox wisdom` (or `make wisdom`). Not in --help:
easter eggs don't advertise, they wait.
"""

FRAME = """
    ┌────────────────────────────────────────────────────────────┐
    │                           >_                               │
    │                                                            │
    │                    Context suggests;                       │
    │                    boundaries decide;                      │
    │          the gaps between tiers are the price              │
    │              of trusting a suggestion.                     │
    │                                                            │
    │                                                            │
    │               DEDICATED TO RANDAL SCHWARTZ,                │
    │                  who asked for a frame.                    │
    └────────────────────────────────────────────────────────────┘
      SCAR-BENCH-114: 100% trips at ceiling on open weights.
      The canary is a key cut from private history — no prior
      forges what never shipped.

      $ cat wisdom.txt
        Good tools. Better people. Same problems. Still worth it.
      $ _
"""


def print_wisdom() -> None:
    print(FRAME)


if __name__ == "__main__":
    print_wisdom()
