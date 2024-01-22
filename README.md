# ax2txt
Decode raw AX.25 frames from stdin to human-readable form on stdout.

Does not handle removing KISS framing.

Author: Paula G8PZT

## Building

```
apt install git build-essential
git clone https://github.com/Online-Amateur-Radio-Club-M0OUK/ax2txt.git
cd ax2txt
gcc ax2txt.c -o ax2txt
```

## Updating

```
cd ax2txt
git pull
gcc ax2txt.c -o ax2txt
```

## Usage

```
cat myframe.bin | ax2txt
```
