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

## How `update.zip` is signed

The following files in the `META-INF` dicrectory are about verification

	MANIFEST.MF					contains base64-encoded sha1/sha256 digest of each file in the zip
	CERT.SF						SF is for Signature File
								contains base64-encoded sha1/sha256 digest of MANIFEST.MF and each entry in it
	CERT.RSA/CERT.EC			pkcs7-signedData
	com/android/otacert			certificate for signature verification

There must exist also a file in `/system/etc/security/otacerts.zip` the same as `com/android/otacert`.

To make the OEM firmware accept a customized `update.zip`, we need to sign the `update.zip` with our own keys and put the corresponding certificate into `/system/etc/security/otacerts.zip`.  To do this we need to re-mount `/system` with `rw` attribute which requires root privileges.

Inspect the content with openssl

	openssl x509 -in com/android/otacert -noout -text
	# -i for indentation according to depth
	openssl asn1parse -in com/android/otacert -i

	openssl asn1parse -in CERT.RSA -inform DER -i
	# extract certificate from cert.pem.  It should have the same parameters as
	# com/android/otacert though possibly differnt checksum
	openssl pkcs7 -in CERT.RSA -inform DER -print_certs -out cert.pem

	# -noverify disables verification of signers of a signed message
	openssl smime -noverify -verify -in CERT.RSA -inform DER -content CERT.SF com/android/otacert

How entries in `CERT.SF` are generated

	# The first 3 lines of CERT.SF contain base64-encoded digest of the whole MANIFEST.MF
	#
	#	Signature-Version: 1.0
	#	Created-By: 1.0 (Android SignApk)
	#	SHA1-Digest-Manifest: vBqgtaM2XU2iSXDw/GTFH4vdYBM=
	#
	# A entry in MANIFEST.MF
	s = (
		"Name: custom/3rd-party/apk/Alipay.apk\r\n"
		"SHA1-Digest: 9x4MgXHxkGneHJuHfvLBe+GCdlY=\r\n"
		"\r\n"
	)

	import hashlib
	import base64

	s1 = hashlib.sha1()
	s1.update(s)
	d = s1.digest()
	# SHA1-Digest-Manifest: ImJbqdPG1KTXNcTon1SgR4Cl+E0=
	print base64.b64encode(d)

Links

- tools/signapk/src/com/android/signapk, https://android.googlesource.com/platform/build
- Android code signing, https://nelenkov.blogspot.com/2013/04/android-code-signing.html

## Credits

- [Tool]Converter Bin-to-Zip, http://forum.xda-developers.com/showthread.php?t=1983985
- AES Crypt™, https://www.aescrypt.com/
