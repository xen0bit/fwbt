# fwbt

Writeup: https://www.labs.greynoise.io/grimoire/2024-08-20-bluuid-firewalla/

Proof of Concept code for interaction with Firewalla via Bluetooth Low-Energy and exploitation of CVE-2024-40892 / CVE-2024-40893

Without any configuration it will scan for Firewalla's in local proximity and leak the checksum of the License UUID.

If License UUID is obtained, it can be defined at `var myLicense = ""` in `main.go` at which point:

1. A local backup of the device configuration will be made.
2. If the device configuration is already backed up:
3. Generate root SSH credentials (CVE-2024-40892)
4. Exploit 3 command injection vulnerabilites (CVE-2024-40893)

