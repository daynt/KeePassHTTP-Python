# KeePassHTTP-Python
python class to comminutate with keepass

## Prerequisite
```bash
pip install pyyaml pycrypto
```

## Known Issue
* Python3 import error on Windows
```bash
ImportError: No module named 'winrandom'
```
* Solution
Fix it in file $(Python)\Lib\site-packages\pycrypto-2.6.1-py3.5-win32.egg\Crypto\Random\OSRNG\nt.py

```python
- import winrandom
+ from .import winrandom
```