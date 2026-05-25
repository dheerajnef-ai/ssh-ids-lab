# ssh-ids-lab

SSH failed-login checker: read auth logs, count by IP + username, alert over a threshold.

## Clone

```bash
git clone https://github.com/dheerajnef-ai/ssh-ids-lab.git
cd ssh-ids-lab
python3 ssh_ids.py --file "sample_auth (sample).log"
```

Replace `YOUR_USERNAME` with your GitHub username after you create the repo.

## Files

- `ssh_ids.py` — script
- `sample_auth (sample).log` — offline practice log
- `alerts.log` — optional; only created when you run with `--alert-log alerts.log`

## Test

1. Sample: `python3 ssh_ids.py --file "sample_auth (sample).log"`
2. Mac live: enable Remote Login, fail SSH password a few times, then  
   `python3 ssh_ids.py --live --minutes 15 --threshold 3 --timeline`

## Requirements

Python 3. macOS for `--live` mode.
