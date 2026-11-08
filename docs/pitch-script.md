# Pitch script (draft): 5–7 minutes, in English

The words we say on stage, in the order the brief asks: problem, demo, numbers, trade-offs, limitations, next steps.
Then the jury's 8 minutes of live checks (`docs/jury-demo.md`). Every sentence that claims something is a row of
`PITCH.md` with a passing test; the bracket after it names the row. Nothing here claims more than that table.

**Speakers.** At least two, juniors and seniors both speak (the brief). The draft splits it in two:
- **Speaker 1**: problem, numbers, next steps.
- **Speaker 2**: the demo, trade-offs, limitations.
- **At the laptop**: one person clicks through the demo while Speaker 2 talks (it can be Speaker 2).

Fill in the names when we choose them. About 120–130 spoken words a minute: the spoken parts below are about 700
words, so about 5½ minutes of talk and 6 to 6½ with the demo's clicks and Tuga's voice. Under 5 minutes is as bad as
over 7: rehearse with a timer.

**Before we start:** the laptop on Acasă, Romanian, Simple mode, `V2_smart_home.xml` picked, the sound on, and the
Romanian voice (Microsoft Andrei) installed: Settings → Time & language → Speech. Without it Tuga shows how to add a
voice instead of reading.

---

## 1. The problem (0:00–0:40) · Speaker 1

> A camera at the door, a smart TV, a router nobody has opened since it was installed. Each one is a small computer
> on your network, and each one can leave a door open.
>
> The tool that finds those doors, nmap, writes for experts. Our grandparents, or a twelve-year-old, can't read it,
> and they shouldn't have to.
>
> So we built **ConeTuga**: it tells you which device is the most dangerous and what to do first, in words anyone
> understands.

## 2. The demo (0:40–3:10) · Speaker 2, with the laptop

**[Acasă is on screen, V2 picked. Tap Tuga's picture.]**

> This is Tuga, our tortoise. He is slow and patient, and he explains things in plain words. Tap him, and he reads
> the result aloud.

*(Tuga reads the headline and the score. Let him finish the first sentence, then tap again to stop.)*

> He uses a voice that is already on your computer: nothing is sent online and nothing is downloaded. [Reads aloud]
> In short: the camera is the most dangerous device, the first thing to do is change its factory password, and the
> score is 40 out of 100, red.

**[Scroll to "Lista ta de reparat".]**

> Instead of a report, you get a checkup. One task at a time, the one worth the most first, at most three steps in
> plain words. [Checkup] And every task says what it is worth: fixing the camera stream takes this home from 40 to 60.
> [What it is worth]

**[Tick "Am făcut asta" on the first task.]**

> When you are done, you tick it. The estimated score goes up, and the next task opens. It is only an estimate: the
> page tells you to scan again to prove it, and we never pretend otherwise.

**[Scroll to "Casa ta".]**

> And here is your home: every device the scan found, what it is, whether it needs care, and how to recognise it, with
> its MAC address masked. [Masked MACs]

**[Turn on "Avansat (Cone 🐇)" in the sidebar.]**

> For the person who wants the details, there is Cone, the hare. Same findings, same score, same first step; Cone adds
> what nmap actually saw and the catalog rule behind it. [Two guides, one answer]

**[Pick `scan_01.xml`, then `scan_03.xml`; show the history.]**

> And this is our own lab, on our own hotspot. Our first scan scored 0. We turned telnet and FTP off: 50. We turned
> Redis off: 70. The history shows each fix as resolved, and nothing new. [Lab 0 → 70]

## 3. The numbers (3:10–4:20) · Speaker 1

> Three numbers.
>
> **One: correctness.** On the Validation Set we reproduce all 24 findings, with no extra row, and every score.
> [24 of 24] Same file, same result, every time: no AI ever decides a finding. [Same file, same result]
>
> **Two: safety.** A live scan runs only on our hotspot, only with an explicit confirm, at most 100 packets a second.
> [Live scan] The tool refuses public addresses and anything outside our network. [Refuses public IPs] And a hostile
> or broken scan file can't trick it: it gets a clear error, and the other files still run. [Hostile file, Broken file]
>
> **Three: everyone can use it.** We checked every page with axe-core against WCAG 2.1 AA, in the light and the dark
> theme: zero violations, no text under 16 pixels, buttons at least 48 pixels, and with "reduce motion" nothing
> moves. [Accessible, Big targets]
>
> Behind all this: over a thousand automated tests, green on Linux and Windows on every change.

## 4. Trade-offs (4:20–5:15) · Speaker 2

> Four choices, on purpose.
>
> **Exact over clever.** Findings come only from the official catalog, so your re-run will match our upload exactly;
> the price is that we report only what nmap names.
>
> **No language model deciding.** Fixed, reviewed texts in Romanian and English; the question box answers only from
> the scan and cites its finding. [Ask in plain words] Nothing invented, no key to leak.
>
> **Safety over speed.** A hundred packets a second: our lab takes about three and a half minutes, a busy home longer.
>
> **Privacy by default.** Masked MACs, a history that stays on your computer and one button to delete it. Even Tuga's
> voice stays local.

## 5. Limitations (5:15–5:45) · Speaker 2

> And what it doesn't do yet. A live scan can miss an open MQTT broker, because nmap renames the service. The history
> follows devices by address, so a device that gets a new address looks new. Tuga reads aloud only if the computer has
> a voice in your language. And the checkup trusts your tick until you scan again.

## 6. Next steps (5:45–6:20) · Speaker 1

> Next: a one-click rescan from the page, so the loop "fix, rescan, resolved" happens without a terminal. Fix steps
> written for your exact router model. And an optional local model that only rephrases our text, with every sentence
> checked against the scan.
>
> ConeTuga: the most dangerous device first, what to do about it, in words anyone understands. Thank you. We're ready
> for your checks.

---

## Claims used, and their rows in `PITCH.md`

| Said on stage | `PITCH.md` row (start of the claim) |
|---|---|
| reads aloud, nothing sent online | "Tap Tuga and he reads the result aloud…" |
| checkup, one task at a time | "A checkup a grandparent can follow…" |
| 40 → 60 | "Every fix says what it is worth…" |
| masked MAC | "MAC addresses are masked everywhere." |
| Cone, same answer | "Two guides, one answer…" |
| lab 0 → 50 → 70 | "In our own lab, two fixes took the score from 0 to 70…" |
| 24 of 24 | "We reproduce the Validation Set…" |
| same file, same result | "Same file, same result, every time…" |
| live scan rules | "A live scan runs only on our hotspot…" |
| refuses public IPs | "The tool refuses public IPs…" |
| hostile or broken file | "A hostile scan file can't trick the parser…", "A broken file shows a clear error…" |
| WCAG, 16 px, 48 px, reduce motion | "Accessible on both themes…", "Big targets and calm motion…", and "Numbers for the demo" (axe-core re-run) |
| question box | "Ask in plain words…" |

The numbers "about three and a half minutes" (our lab, ~200 s) and "over a thousand tests" come from "Numbers for the
demo" and the trade-offs in `PITCH.md`, and from the test count on `main`. The zero axe-core violations on the dark
theme hold once #83 is merged.

## Rehearsal checklist
- [ ] Choose the speakers and write their names above; at least one junior and one senior speak.
- [ ] Two full runs with a timer: between 5:30 and 6:45 each.
- [ ] The demo once with the sound on, on the presentation laptop, with the Romanian voice installed.
- [ ] If the voice is missing on the day: skip the tap, read the headline yourself, and say "Tuga can also read it
  aloud with a voice installed on the computer."
- [ ] Hand over to the live checks in `docs/jury-demo.md`, in the jury's order.
