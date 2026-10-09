# Build the extracted specification. Needs pdflatex with amsmath, booktabs,
# tabularx, longtable, xcolor, fancyvrb, hyperref (any TeX Live >= 2020;
# TinyTeX-1 suffices). Two passes resolve the table of contents.
PDFLATEX ?= pdflatex
MAIN      = toy-zk-rollup-spec
OUT      ?= build

.PHONY: all clean
all: $(OUT)/$(MAIN).pdf

$(OUT)/$(MAIN).pdf: $(MAIN).tex preamble.tex sections/*.tex
	mkdir -p $(OUT)
	$(PDFLATEX) -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) $(MAIN).tex
	$(PDFLATEX) -interaction=nonstopmode -halt-on-error -output-directory=$(OUT) $(MAIN).tex
	cp $(OUT)/$(MAIN).pdf $(MAIN).pdf

clean:
	rm -rf $(OUT)
