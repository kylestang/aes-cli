# Changes

Command line interface:

The flag `--command` is now required, instead of positional argument `encrypt` or `decrypt`

```
Usage: aes-cli <OPTIONS>:
  -c [ --command ] arg     command to execute, either 'encrypt' or 'decrypt'
  -i [ --input ] arg       (optional) input file
  -o [ --output ] arg      (optional) output file
  -m [ --mode ] arg (=GCM) set mode of operation, default to GCM
  -k [ --key ] arg         (optional) input key, of length 128, 192, 256 bits
  -h [ --help ]            print this help message and exit
```
