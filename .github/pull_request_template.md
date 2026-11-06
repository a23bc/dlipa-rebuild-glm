## Summary

What changed, and what it costs or saves. Numbers over adjectives: this branch
lives or dies on device measurements, and a change described without them gets
relitigated later.

## Criterion

How a reader tells, from the outside, that this worked. Name the log line, the
file size, the timing, or the flow that now behaves differently -- and say which
build you ran it on.

- [ ] ran on device, build `<commit>`
- [ ] log lines that prove it:

## What is knowingly left

Two things belong here: work this branch deliberately does not do, and levers
that were measured and killed. The second half is the valuable one -- several
"obvious" optimisations here cost more than they saved, and without a record they
come back as new ideas.

- [ ] no Apple binary is bundled, committed, hosted or attached to a release

## Notes for the reviewer

Anything that will look wrong and is not, with the reason.
