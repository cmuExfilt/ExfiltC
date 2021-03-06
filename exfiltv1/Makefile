# Just by typing 'make' will rebuild the book, extract the code, compile it,
# and run it.
all: 
	@ echo 
	@ echo make full ------- makes book, runs sha1 and ear, cleans
	@ echo 
	@ echo make book ------- make the pdf
	@ echo make code ------- runs the sha1 and ear stanzas
	@ echo make ear -------- build and test ear.c
	@ echo make sha1 ------- build and test sha1.c
	@ echo make earandsha1 - build and test earandsha1.c
	@ echo make vhdl ------- extract the VHDL for SHA1
	@ echo 
	@ echo make makefile --- recreate this Makefile
	@ echo make reference -- build the reference file for testing
	@ echo make rfctest ---- run RFC 3174 SHA1 hash test code
	@ echo make clean ------ remove files not checked into git
	@ echo make tangle ----- make tangle for Literate Programming
	@ echo make tgz -------- make a tgz file for shipping
	@ echo 

full: clean book sha1 ear 
	@ make clean

makefile: tangle makefile.tex
	@ ./tangle makefile.tex makefile >Makefile

code: sha1 ear earandsha1

# sha1sum reference.java = 4c963386437a56156a75a7f0da2302eee3ca881a  
sha1: tangle Background.tex reference
	@ ./tangle Background.tex sha1.c >sha1.c
	@ gcc -o sha1 sha1.c
	@ echo running sha1 reference.java refFileOut
	@ rm -f refFileOut
	@ ./sha1 reference.java refFileOut
	@ wc reference.java
	@ wc refFileOut

rfctest: tangle Background.tex 
	@ ./tangle Background.tex rfctest.c >rfctest.c
	@ gcc -o rfctest rfctest.c
	@ echo running rfctest
	@ ./rfctest

ear: tangle FTPDetails.tex
	@ ./tangle FTPDetails.tex ear.c >ear.c
	@ gcc -o ear ear.c
	@ sudo ./ear

earandsha1: tangle FTPDetails.tex
	@ ./tangle FTPDetails.tex earandsha1.c >earandsha1.c
	@ gcc -o earandsha1 earandsha1.c
	@ sudo ./earandsha1

reference.java : reference.tex 
	@ ./tangle reference.tex reference.java >reference.java

reference: reference.tex 
	@ ./tangle reference.tex reference.java >reference.java

vhdl: tangle Sha1FPGA.tex
	@ ./tangle Sha1FPGA.tex sha1.v >sha1.v

# typing 'make book' will create 'exfilt.pdf'
book: clean
	@ latex exfilt.tex && makeindex exfilt.idx && latex exfilt.tex  \
          && dvipdfm exfilt.dvi 
	@ rm -f exfilt.log exfilt.out exfilt.aux exfilt.dvi exfilt.toc
	@ rm -f *~

# the tangle program extracts code from latex sources
tangle: tangle.c
	@ gcc -o tangle tangle.c

# typing 'make tar' will clean up everything and make a tar-gzip file
tgz: clean
	@ ( cd .. ; tar -zcf exfilt.tgz exfilt )

# typing 'make clean' will remove any generated files
clean:
	@ rm -f rfctest* sha1.v
	@ rm -f ear.c ear 
	@ rm -f sha1.c sha1 refFileIn refFileout reference.java
	@ rm -f tangle exfilt.idx exfilt.ild exfilt.ind exfilt.ilg
	@ rm -f exfilt.log exfilt.out exfilt.aux exfilt.dvi exfilt.toc
	@ rm -f *~
	@ rm -f earandsha1 earandsha1.c log.txt

