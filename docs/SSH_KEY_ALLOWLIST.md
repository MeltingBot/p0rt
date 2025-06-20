# SSH Key Allowlist System

The P0rt server can be configured to only allow pre-registered SSH keys, useful for beta programs, freemium models, or VIP access tiers.

## Configuration

### Environment Variables

- `P0RT_AUTHORIZED_KEYS`: Path to the authorized keys JSON file (default: `authorized_keys.json`)
- `P0RT_OPEN_ACCESS`: Set to `true` to allow all keys (open mode, default: restricted)

### Access Tiers

The system supports different access tiers:
- `beta`: Beta testers
- `free`: Free tier users
- `premium`: Premium users
- `vip`: VIP users with special privileges

## Key Management Tool

Use the `keymanager` CLI tool to manage authorized keys:

### Build the tool
```bash
go build -o keymanager cmd/keymanager/main.go
```

### Add a key
```bash
# From file
./keymanager -action add -key-file ~/.ssh/id_rsa.pub -tier beta -comment "John Doe"

# From string
./keymanager -action add -key "ssh-rsa AAAAB3..." -tier premium -comment "Jane Smith"

# With expiration
./keymanager -action add -key-file key.pub -tier beta -expires "2024-12-31T23:59:59Z"

# Interactive (paste key when prompted)
./keymanager -action add -tier free -comment "Test User"
```

### List all keys
```bash
./keymanager -action list
```

### Import keys from authorized_keys file
```bash
./keymanager -action import -import-file ~/.ssh/authorized_keys -tier beta
```

### Deactivate/Activate a key
```bash
# Deactivate (key remains in system but access is denied)
./keymanager -action deactivate -fingerprint "SHA256:xxxxx"

# Reactivate
./keymanager -action activate -fingerprint "SHA256:xxxxx"
```

### Remove a key
```bash
./keymanager -action remove -fingerprint "SHA256:xxxxx"
```

## Running in Different Modes

### Restricted Mode (Default)
Only pre-registered keys can connect:
```bash
P0RT_AUTHORIZED_KEYS=./beta_keys.json ./p0rt
```

### Open Access Mode
All SSH keys are allowed:
```bash
P0RT_OPEN_ACCESS=true ./p0rt
```

## User Experience

When users connect with SSH:

- **Authorized users** see their tier information:
  ```
  P0rt Tunnel Connected
  Access Tier: BETA (John Doe)
  Your tunnel: https://domain.p0rt.xyz
  Local server: localhost:50001
  ```

- **Unauthorized users** receive an authentication error:
  ```
  Permission denied (publickey).
  ```

## Example Workflow for Beta Program

1. Create a beta keys file:
   ```bash
   touch beta_keys.json
   ```

2. Add beta testers:
   ```bash
   ./keymanager -action add -key-file john.pub -tier beta -comment "John - Early Tester"
   ./keymanager -action add -key-file jane.pub -tier beta -comment "Jane - Feedback Provider"
   ```

3. Run server with beta keys:
   ```bash
   P0RT_AUTHORIZED_KEYS=beta_keys.json ./p0rt
   ```

4. Gradually add more users or switch to open access:
   ```bash
   # Add more beta users
   ./keymanager -action import -import-file new_beta_users.keys -tier beta
   
   # Or switch to open access
   P0RT_OPEN_ACCESS=true ./p0rt
   ```

## Security Considerations

- The authorized keys file should be kept secure and backed up
- Keys are identified by their SHA256 fingerprint
- Deactivated keys remain in the system for audit purposes
- Expired keys are automatically denied access
- The system still enforces all other security measures (rate limiting, IP bans, etc.)