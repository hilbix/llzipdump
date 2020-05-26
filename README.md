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
	else: unknown zip format

## FAQ

WTF why?

- Because ZIP files can contain information which is hidden from unzip, zipdetails and zipinfo as well.

License?

- Free as in free beer, free speech, free baby

