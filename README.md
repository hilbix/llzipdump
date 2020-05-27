# llzipdump

LowLevel dump of ZIP files, when all other tools leave you completely in the dark.

## Usage

	git clone https://github.com/hilbix/llzipdump.git
	cd llzipdump
	make
	sudo make install

Then:

	llzipdump file.zip..
	llzipdump file.zip - > clean.zip
	llzipdump - < file.zip
	llzipdump - - < dirty.zip > clean.zip

Return code:

	0 zip is clean
	1 zip is not clean
	else: something is broken


## TODO

- CRC32 is not checked.  So currently you need other tools for this.

- Add more ZIP variants.  If you find one which is not processed correctly,
  pease open an issue on GH and do not forget to add a link to the ZIP file!
  (Without a sample ZIP I certainly cannot fix it.)


## FAQ

WTF why?

- Because ZIP files can contain information which is hidden from unzip, zipdetails and zipinfo as well.

License?

- Free as in free beer, free speech, free baby
