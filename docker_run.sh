#!/bin/bash

sudo docker run --rm \
	-v `pwd`:/data \
	-w /data \
	rstropek/pandoc-latex \
	-f markdown \
	--template https://raw.githubusercontent.com/Wandmalfarbe/pandoc-latex-template/5f740f8de0fb4c96dfb2772ef86e861fd3971654/eisvogel.tex \
	-t latex \
	-o report/$2/OSCP-$1-Exam-Report.pdf --listings report/$2/OSCP-$1-Exam-Report.md

xdg-open report/$2/OSCP-$1-Exam-Report.pdf

