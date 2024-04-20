pandoc -f markdown+latex_macros -t pdf -o writeup.pdf -V geometry:margin=1in -V papersize:a4 -s --shift-heading-level-by -1 --pdf-engine xelatex --highlight-style tango ./writeup.md
