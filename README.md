<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/db834dd7-6c0e-43d0-806d-54d16c8d338e" />

# 🫯 Black Zinc Beacon

A lightweight ARM beacon designed for use in Android, Raspberry Pi, and Orange Pi devices.

## 🫈 About

BlackZinc Beacon is a custom C2 beacon focused on ARM architecture, supporting ARM Linux environments such as Android, Raspberry Pi, and Orange Pi. It is designed for stealth, low memory footprint, and secure communications using AES-256 CFB encryption, making it ideal for offensive security operations and red team engagements.

## 🫪 Features

- Cross-platform ARM support (Android, Raspberry Pi, Orange Pi)
- AES-256 CFB encryption for secure communication
- Customizable malleable C2 profiles
- Lightweight, production-ready code with strict memory safety
- Integration with curl and Bionic libc
- No hardcoded dependencies: modular and easy to compile

## 🪊 Installation

```bash
make
```

```text

## Usage

- Configure `C2_URL`, `CLIENT_ID`, `MALEABLE`, and other constants in `beacon.c`.
- Compile for your target ARM platform:
make
```
```text
- Deploy on ARM Linux device (Android, Raspberry Pi, Orange Pi).
- Beacon will register and check for commands at regular intervals.
```
## 🪎 Security

- Full memory safety practices (buffer overflow prevention, strict validation, snprintf usage)
- No hardcoded secrets in production
- Security hardened build flags recommended

## 🛘 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 🌱 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🫍 Code of Conduct

Please follow the code of conduct for community participation.

## 🎓 Educational Purpose
This project is intended to:

- Help red teams understand modern C2 evasion techniques.
- Assist blue teams in developing better detection logic.
- Promote research into secure software design and defensive hardening.
- Demonstrate the importance of runtime analysis over static signatures.

## ⚠️ DISCLAIMER - NO WARRANTY OR LIABILITY
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## 🔗 Links
- https://deepwiki.com/grisuno/beacon
- https://deepwiki.com/grisuno/blacksandbeacon
- https://github.com/grisuno/BlackObsidianC2
- https://github.com/grisuno/LazyOwn
- https://grisuno.github.io/LazyOwn/
- https://www.reddit.com/r/LazyOwn/
- https://github.com/grisuno/LazyOwnBT
- https://web.facebook.com/profile.php?id=61560596232150
- https://app.hackthebox.com/teams/overview/6429
- https://app.hackthebox.com/users/1998024
- https://patreon.com/LazyOwn
- https://deepwiki.com/grisuno/ebird3
- https://deepwiki.com/grisuno/hellbird
- https://github.com/grisuno/cgoblin
- https://github.com/grisuno/gomulti_loader
- https://github.com/grisuno/ShadowLink
- https://github.com/grisuno/OverRide
- https://github.com/grisuno/amsi
- https://medium.com/@lazyown.redteam
- https://discord.gg/V3usU8yH
- https://ko-fi.com/Y8Y2Z73AV
- https://medium.com/@lazyown.redteam/black-basalt-beacon-when-your-coff-loader-becomes-a-silent-operator-and-why-thats-by-design-not-4094c92a73a5
- https://github.com/grisuno/LazyOwn/archive/refs/tags/release/0.2.61.tar.gz

![jimeng-2025-06-29-179-Cyberpunk-style logo for 'LazyOwn RedTeam', hacking_pen-testing tool  Colors_ ](https://github.com/user-attachments/assets/83d366ef-f899-4416-8559-20bd9fd34ef4)

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
