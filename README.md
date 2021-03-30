[![Build Status](https://api.cirrus-ci.com/github/hilbix/llzipdump.svg)](https://cirrus-ci.com/github/hilbix/llzipdump)

> This is terribly incomplete for now
>
> However following is already useful on JARs and APKs:
>
> - `./llzipdump ZIP >/dev/null; echo $?` and if this returns 1 then
> - `./llzipdump ZIP | less '+/ Garbage$'`
>
> If you see something like `APK Sig Block 42` on the end of the Garbage,
> have a look at https://source.android.com/security/apksigning

# llzipdump

LowLevel dump of ZIP files, when all other tools leave you completely in the dark.

## Usage

	git clone https://github.com/hilbix/llzipdump.git
	cd llzipdump
	make all
	sudo make install

Then:

	llzipdump file.zip..
	llzipdump - < file.zip

Return code:

	0 zip is clean
	1 zip is not clean
	else: something is broken

In future I want the tool to be able to clean the ZIP file:

	llzipdump -1 -- files.zip - > clean.zip
	llzipdump -1 - < dirty.zip > clean.zip

Please note that this then would wipe the APK signature,
see https://source.android.com/security/apksigning


## TODO/BUGs

- This is terribly incomplete (see `NOTYET` in the source)

- Probably does not work for ZIP64 archives

- Probably does not work for progressive archives (which cannot seek)

- Probably does not work for split ZIP files

- Fails on encrypted archives (does not grok encryption records yet)

- CRC32 is not checked.  So currently you need other tools for this

- Add more ZIP variants.  If you find one which is not processed correctly,
  pease open an issue on GH and do not forget to add a link to the ZIP file!
  (Without a sample ZIP I certainly cannot fix it.)

- The central directory is not compared with the file entries.
  In fact this program just dumps things and does not interpret them.

## FAQ

WTF why?

- Because ZIP files can contain information which is hidden from unzip, zipdetails and zipinfo as well.

License?

- Free as in free beer, free speech, free baby

