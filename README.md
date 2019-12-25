
### Teeworlds ECON VPN Detection
Create a new file `~/.env`

The file must contain your configuration, access token, etc:
```
# .env
IPHUB_TOKEN=<your https://iphub.info key>
EMAIL=<a proper existing email!>

ECON_HOST=<your econ bind_addr, e.g. 127.0.0.1>
ECON_PORT=<your econ port>
ECON_PASSWORD=<your econ password>

# ban time in minutes
VPN_BAN_TIME=1440
VPN_BAN_REASON=VPN
```

### Requirements
You need to have redis installed.
Redis is being used as a caching database.
Redis is a lightweight and high performance key value store, that has a footprint of only a few MB.

### Database dependencies
```
# macOS
brew install redis

# Debian/Ubuntu
sudo apt install redis
```

### Python dependencies:
```
pip3 install aiohttp python-dotenv redis hiredis
```

### Add the script to automatically start on reboot.
```
crontab -e
```

Add a new line:
```
@reboot TeeworldsEconVPNDetection/./main.py
```
