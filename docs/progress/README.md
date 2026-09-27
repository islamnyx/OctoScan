# Progress logs
One file per teammate: `docs/progress/<name>.md`. Append-only, newest entry at the bottom.
Every AI tool reads ALL files here before starting work and appends to its own owner's file
after finishing a task. Entry format:

## HH:MM - <short title>
- Done: what changed (files, endpoints, models)
- State: works / partial / broken, how it was tested
- Next: the next step or open problem
- Decisions: anything the team must know (contract change, model choice, gotcha)
