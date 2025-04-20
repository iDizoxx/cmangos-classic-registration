# cmangos-classic-registration
cMaNGOS Classic (1.12.1) Vanilla registration page with explanation of SERPv2 verifier.

# CMaNGOS Classic SRP6v2 Registration Guide (PHP)

This guide explains how to implement a secure, working registration system for **CMaNGOS Classic WoW servers** using **PHP**, **MySQL**, and **SRP6v2**.

---

## Requirements

### PHP Extensions
- `gmp` — for SRP6 large-number math.
- `pdo_mysql` — for database connection.

### Database
- **Database**: `classicrealmd`
- **Table**: `account`
- **Relevant Columns**:
  - `username`: `VARCHAR(32)` — must be **UPPERCASE**
  - `s`: `VARCHAR(64)` — SRP6 salt (hex string)
  - `v`: `VARCHAR(64)` — SRP6 verifier (hex string)
  - `email`: `VARCHAR(254)`
  - `expansion`: `TINYINT` (default `1` for Classic)

---

## SRP6v2 Algorithm (CMaNGOS Logic)

### What is SRP6?
SRP6 (Secure Remote Password protocol version 6) is a secure password-authentication method used by WoW clients to log in without sending the actual password. It uses a salt and verifier.

### Key Constants
```php
$g = gmp_init(7);
$N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);
```

### Process Summary

1. Generate a 32-byte random `salt`.
2. Calculate `x` as:
   ```php
   $h1 = sha1(strtoupper($username . ':' . $password), true);
   $h2 = sha1(strrev($salt) . $h1, true); // Reverse salt for CMaNGOS
   $x = gmp_import($h2, 1, GMP_LSW_FIRST);
   ```
3. Calculate verifier `v`:
   ```php
   $v = gmp_powm($g, $x, $N);
   ```
4. Convert verifier to 32-byte little-endian binary:
   ```php
   $verifier = gmp_export($v, 1, GMP_LSW_FIRST);
   $verifier = str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);
   ```
5. Reverse verifier and convert both values to uppercase hex:
   ```php
   $salt_hex = strtoupper(bin2hex($salt));
   $verifier_hex = strtoupper(bin2hex(strrev($verifier)));
   ```

These two values are stored as `s` and `v` in the `account` table.

---

## Example SQL Insert
```sql
INSERT INTO account (username, s, v, email, expansion)
VALUES ('USERNAME', 'SALT_IN_HEX', 'VERIFIER_IN_HEX', 'EMAIL@EXAMPLE.COM', 1);
```

---

## PHP Registration Example
See [`register.php`](./register.php) for a full working example.

---

## Common Issues
| Problem | Cause | Fix |
|--------|-------|-----|
| Stuck at "Connecting..." | Incorrect salt/verifier logic | Ensure you're reversing salt and verifier for `server_core = 5` |
| Username duplicates | Not normalized | Always store and query with `UPPERCASE(username)` |
| GMP errors | Missing extension | Install with `apt install php-gmp` or enable in `php.ini` |

---

## Additional Notes
- Always validate and sanitize user input.
- Consider adding:
  - reCAPTCHA/hCaptcha
  - Email confirmation
  - IP restrictions or throttling

---

## License
Feel free to use, modify, and distribute this under the MIT License.

---

## Credits
- Based on logic from TrinityCore / CMaNGOS
- Protocol: Secure Remote Password v6 (SRP6)
- GMP-based implementation for PHP

---

For questions or contributions, open an issue or pull request on GitHub!

