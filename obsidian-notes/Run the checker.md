# Run the checker

[[START HERE]] · [[Sample log (sample)]]

Test with **real** failed SSH logins on your Mac.

Only use your own machine. Do not test against random hosts on the internet.

---

## Before you start

- Project at `~/ssh-ids-lab` (see [[START HERE]])
- **Python 3** installed
- Sample test done optional: [[Sample log (sample)]]

---

## Part A — Clone or open the project

If you have not cloned yet, see [[START HERE#Get the project on your Mac (from GitHub)|START HERE → clone steps]].

```bash
cd ~/ssh-ids-lab
ls ssh_ids.py
```

Run commands from this folder (not Desktop) if macOS says `Operation not permitted`.

---

## Part B — Turn on SSH on Mac

1. **System Settings**
2. **General** → **Sharing** (or **Sharing** in the sidebar)
3. **Remote Login** → **On**
4. Note your Mac username (the one you use to log in)

Check:

```bash
ssh YOUR_USERNAME@127.0.0.1
```

- `Connection refused` → Remote Login still off  
- `Password:` → OK, go to Part C  

`127.0.0.1` = this Mac.

---

## Part C — Make failed logins (wrong password only)

```bash
ssh YOUR_USERNAME@127.0.0.1
```

Enter a **wrong** password at least **4 times**. Do **not** log in with the correct password.

You may see:

```text
Permission denied, please try again.
```

Press **Ctrl+C** to exit SSH.

macOS writes lines like:

```text
PAM: authentication error for YOUR_USERNAME from 127.0.0.1
```

Passwords are **not** stored in the log.

---

## Part D — Run the script

```bash
cd ~/ssh-ids-lab
python3 ssh_ids.py --live --minutes 15 --threshold 3 --timeline --alert-log alerts.log
```

| Flag | Meaning |
|------|--------|
| `--live` | Read Mac system logs for sshd |
| `--minutes 15` | Last 15 minutes only |
| `--threshold 3` | Alert if ≥ 3 failures for same IP + user |
| `--timeline` | List each failure time |
| `--alert-log alerts.log` | Optional: saves one line per alert to `alerts.log` (file created by you, not shipped with repo) |

---

## Part E — Read the result

Example:

```text
Parsed 3 failed SSH login(s).
127.0.0.1   yourusername   3   ...   ALERT
```

- **Parsed** = failure lines found in that time window  
- **COUNT** = total failures (can be 6, 12, etc. — not cut to 3)  
- **ALERT** = COUNT ≥ threshold  

---

## Part F — Extra checks (optional)

**Raw Mac log (24h):**

```bash
/usr/bin/log show --style syslog --last 24h --predicate 'process == "sshd" AND eventMessage CONTAINS "authentication error"'
```

**Script on last 24h:**

```bash
python3 ssh_ids.py --live --minutes 1440 --threshold 3 --timeline
```

**Alert history:**

```bash
grep ALERT ~/ssh-ids-lab/alerts.log
grep -c ALERT ~/ssh-ids-lab/alerts.log
```

Run each `grep` on its own line (no comment text on the same line).

---

## If something fails

| Problem | What to do |
|---------|------------|
| `Connection refused` | Remote Login on (Part B) |
| `Parsed 0` | Part C again, then Part D within 15 minutes |
| `Operation not permitted` | `cd ~/ssh-ids-lab`, not Desktop |
| Fewer failures than password tries | Normal — logs count auth errors, not every keypress |

---

## Offline instead

[[Sample log (sample)]]
