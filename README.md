# ax2txt
Decode raw AX.25 frames from stdin to human-readable form on stdout.

Does not handle removing KISS framing.

## Building

```
apt install git build-essential
git clone https://github.com/Online-Amateur-Radio-Club-M0OUK/ax2txt.git
cd ax2txt
gcc
mv a.out ax2txt
```

## Usage

```
cat myframe.bin | ax2txt
```
