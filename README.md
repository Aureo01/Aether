# Aether

A **classification‑driven fuzzing engine** that doesn’t just spray payloads and pray.

Vortex fuzzes endpoints, compares everything against a baseline,  
and **classifies responses automatically** so you know what actually matters.

Think less noise. More signal. 

---

## Why Vortex exists

Traditional fuzzing gives you:
- tons of responses
- zero context
- manual diff hell

Vortex flips that around.

It asks:
> “What changed compared to baseline?”  
> “How different is it?”  
> “Is this interesting… or just noise?”

And then answers that for you.

---

## What it does

1. Takes a URL with a `FUZZ` placeholder  
2. Gets a **baseline response**
3. Injects payloads (path or params)
4. Compares every response against baseline using:
   - status codes
   - content length
   - response timing
   - content similarity
5. **Classifies results automatically**

No guessing. No eyeballing diffs at 3am.

---

## Classification logic

Each payload is classified into one of these buckets:

### normal
Response matches baseline.
Probably boring. Move on.

---

### unauthorized_access
Payload causes a **200 OK** where baseline wasn’t.

👀 Very spicy. Check auth / access control.

---

### status_change
Different HTTP status than baseline.

Useful for logic bugs, filters, edge cases.

---

### server_error
Payload triggers `500 / 502 / 503`.

Crash = signal.

---

### timing_anomaly
Response is **significantly slower** than baseline.

Potential:
- regex DoS
- backend heavy processing
- time-based bugs

---

### content_change
Response body **differs significantly** from baseline.

Often where real bugs live.

---

## Smart diffing

Vortex doesn’t just compare sizes.

It uses:
- content hashes
- similarity ratios (SequenceMatcher)
- proportional size deltas
- response timing multipliers

So:
- templates don’t fool it
- dynamic content is handled better
- real changes stand out

---

## Usage

Basic run:

```bash
python3 aether.py \
  -u "https://target.com/api/v1/users/FUZZ/profile" \
  -w payloads.txt

POST requests:

python3 aether.py \
  -u "https://target.com/api/v1/login?user=FUZZ" \
  -w payloads.txt \
  -m POST

Custom headers:

python3 aether.py \
  -u "https://target.com/api/FUZZ" \
  -w payloads.txt \
  -H "Authorization: Bearer token"

