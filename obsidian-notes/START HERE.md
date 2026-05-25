# START HERE — SSH IDS lab

Open this page first.

---

## What this project is

Python script that reads SSH **failed login** lines from a log file or from macOS system logs, counts failures per **IP + username**, and prints **ALERT** when the count hits a limit you set.

Small blue-team exercise: logs → count → alert.

---

## What is in this folder (Obsidian)

Three notes only:

- **START HERE** — you are here
- **Sample log (sample)** — test with a fake log file (no SSH)
- **Run the checker** — test with real Mac logs (SSH on, wrong passwords)

---

## Files in the Git repo

After you clone, your Mac folder looks like:

```text
~/ssh-ids-lab/
  ssh_ids.py
  sample_auth (sample).log
```

**`alerts.log`** — only appears if **you** run the script with `--alert-log alerts.log`. The script appends a line each time it fires an alert. You can delete this file anytime; it is not required to run the project.

---

## Get the project on your Mac (from GitHub)

You need **Python 3**:

```bash
python3 --version
```

### First time — clone the repository

Replace the URL with your real repo after you push to GitHub:

```bash
cd ~
git clone https://github.com/dheerajnef-ai/ssh-ids-lab.git
cd ssh-ids-lab
ls ssh_ids.py
```

You should see `ssh_ids.py` listed.

### Already cloned — update the code

```bash
cd ~/ssh-ids-lab
git pull
```

### Check it is ready

```bash
cd ~/ssh-ids-lab
python3 ssh_ids.py --file "sample_auth (sample).log"
```

If you get a table with IP `10.0.0.55` and maybe **ALERT**, the install is fine.

**Tip:** Run from `~/ssh-ids-lab`, not from Desktop, if macOS shows `Operation not permitted`.

---

## How to test (order)

1. **Sample (offline)** — [[Sample log (sample)]]  
   Fake log only. No SSH settings.

2. **Live Mac** — [[Run the checker]]  
   Remote Login on, wrong passwords, then run `--live`.

---

## Links

- [[Run the checker]]
- [[Sample log (sample)]]
