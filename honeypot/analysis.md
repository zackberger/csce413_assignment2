# Honeypot Analysis

## Summary of Observed Attacks

The honeypot was deployed as a fake SSH service listening on container port 22 and exposed on host port 2222. After deployment, a connection attempt was observed from the host system at IP address `172.20.0.1`.

During this interaction, the client did not initially present a valid SSH banner, indicating the use of a simple TCP client rather than a full SSH implementation. The honeypot then prompted for authentication credentials. The attacker attempted to authenticate using the credentials:

- **Username:** `admin`  
- **Password:** `password`

This authentication attempt failed as expected. The session remained open for approximately **30.84 seconds** before terminating after the failed login attempt. In total, **15 bytes** of data were received during the session.

All activity was successfully captured in the honeypot log file, including timestamps, source IP and port, credential attempts, and session duration.

---

## Notable Patterns

Several common attack behaviors were observed:

- The use of a **default administrative username (`admin`)**, which is commonly targeted during automated or manual credential-stuffing attacks.
- The use of a **weak and commonly guessed password (`password`)**, indicating low-effort reconnaissance rather than a targeted attack.
- The absence of a valid SSH client banner, suggesting the attacker used a lightweight tool (such as `netcat`) rather than a full SSH client.
- The attacker remained connected briefly after the failed login, which is consistent with probing behavior rather than interactive use.

Although this was a controlled test, the behavior closely resembles real-world opportunistic SSH attacks observed on exposed systems.

---

## Recommendations

Based on the honeypot observations, the following defensive measures are recommended:

1. **Disable direct SSH exposure** to untrusted networks whenever possible.
2. **Use key-based authentication** instead of password-based SSH logins.
3. **Enforce strong credential policies** and prevent the use of default usernames.
4. **Implement intrusion detection and alerting**, such as triggering alerts after repeated failed login attempts.
5. **Deploy honeypots in production environments** to collect intelligence on attacker behavior without risking real services.

The honeypot proved effective at capturing attacker interaction data while preventing access to any legitimate system resources.
