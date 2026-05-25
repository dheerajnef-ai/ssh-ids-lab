# Sample log (sample)

[[START HERE]] · [[Run the checker]]

Test the script **without** SSH. Uses a fake Linux-style log file.

---

## What the sample file is

| | |
|---|---|
| File | `~/ssh-ids-lab/sample_auth (sample).log` |
| Content | Made-up failed SSH lines (IP `10.0.0.55`, users like `admin`) |
| Real? | No — practice only |

`(sample)` in the name means it is not from your Mac today.

---

## Steps

**1. Open Terminal**

**2. Go to the project**

```bash
cd ~/ssh-ids-lab
```

**3. Run on the sample file**

```bash
python3 ssh_ids.py --file "sample_auth (sample).log"
```

**4. Optional — show each failure time**

```bash
python3 ssh_ids.py --file "sample_auth (sample).log" --timeline
```

**5. Optional — save alert to `alerts.log`**

Only if you want a history file on disk (the script creates it on first use):

```bash
python3 ssh_ids.py --file "sample_auth (sample).log" --threshold 5 --alert-log alerts.log
```

---

## What good output looks like

You should see a table with IP `10.0.0.55`, user `admin`, **COUNT** around 6, and **ALERT** if count ≥ threshold (default 5).

- **COUNT** = failures found in the log  
- **ALERT** = count reached your threshold  
- Threshold does **not** hide extra failures; it only decides when to alarm

---

## Next

Real Mac test: [[Run the checker]]
