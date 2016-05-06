A glance of usage output

	Usage: ./mkmzupdate -m <model> -e|-d [-i FILE] [-o FILE]
	Encrypt or decrypt firmware for use with MEIZU devices.

		-m, --model     model name, e.g. mx3, etc.
		-i, --input     input file (defaults to stdin)
		-o, --output    output file (defaults to stdout)
		-e, --encrypt   encrypt image
		-d, --decrypt   decrypt image
		-h, --help      show this help text

	Currently supported models: mx3 mx2 mx

Decrypt and encrypt between `update.bin` and `update.zip`

	./mkmzupdate -d -m mx3 -i MX3.Flyme.OS.4.5.7.1A.bin -o x.zip
	./mkmzupdate -e -m mx3 -i x.zip -o x.bin

## Credits

- [Tool]Converter Bin-to-Zip, http://forum.xda-developers.com/showthread.php?t=1983985
- AES Crypt™, https://www.aescrypt.com/
