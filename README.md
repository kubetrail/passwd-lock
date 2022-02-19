# passwd-lock
A CLI tool to encrypt/decrypt files using password based symmetric AES encryption

## disclaimer
>The use of this tool does not guarantee security or suitability
for any particular use. Please review the code and use at your own risk.

## installation
This step assumes you have [Go compiler toolchain](https://go.dev/dl/)
installed on your system.

Download the code to a folder and cd to the folder, then run
```bash
go install
```
Install shell completion. For instance `bash` completion can be installed
by adding following line to your `.bashrc`:
```bash
source <(passwd-lock completion bash)
```

## note
> This tool is intended for easy encryption and decryption needs on small files.
> Please refer to [cipher](https://github.com/kubetrail/cipher) to encrypt/decrypt
> using multi-layered RSA/AES systems for large files.

## encrypt data
```bash
passwd-lock encrypt --plaintext sample.txt
Enter encryption password (min 8 char): 
Enter encryption password again: 
```

This will produce a file `sample.txt.ciphertext` by default. Alternatively,
a ciphertext filename can be entered using `--ciphertext` flag.

## decrypt data
Enter the same password that was used to encrypt the data
```bash
passwd-lock decrypt --ciphertext sample.txt.ciphertext
Enter password used during encryption: 
```

This will produce a file `sample.txt.ciphertext.plaintext` by default. Alternatively,
a plaintext filename can be entered using `--plaintext` flag.

## verify
```bash
md5sum sample.txt*
c525cf80ef7d2cdba9fe4df68e1e4254  sample.txt
cd5bd0943c0fb75e3d7795265f38bd1c  sample.txt.ciphertext
c525cf80ef7d2cdba9fe4df68e1e4254  sample.txt.ciphertext.plaintext
```

As you can see the original file `sample.txt` and the decrypted file `sample.txt.ciphertext.plaintext`
match.
