# Cherrypy-report
Create a PDF from your pentesting cherrytree notes (with the OSCP exam in mind).

## Status
I'm currently testing and refactoring code as well as creating a proper README. **I do not advise you to use the script for your exam just yet. I made this repository public for testing purposes.**


## Requirements

* docker
* python3

## Installation

Clone the project and install the required python(3) modules:

I recommend creating a virtual environment:

```console
git clone https://github.com/gpalo/cherrypy-report.git && cd cherrypy-report
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Or install globally if you really want...

```console
git clone https://github.com/gpalo/cherrypy-report.git && cd cherrypy-report
pip install -r requirements.txt
```

## Running the example
You can run the examples with the following command:

### extensive template
```console
./cherrypy_autoreport.py cherrytree-templates/example-cherrytree.ctb
```

### simple template (automatically fetching CVE details not working yet for this one)
```console
./cherrypy_autoreport.py cherrytree-templates/simple-example-cherrytree.ctb
```

## Motivation for this project

The reporting side of the PWK exam (to me) was the most frustrating and timeconsuming part for various reasons. I had a well organised cherrytree document and it took me hours and hours to translate that into a proper text document. This tool is an attempt to automate this process. As of right now it is specifically made with the OSCP exam in mind. 

## How it works

This script uses a (specially formatted) cherrytree ctb file (which is just a sqlite3 database) to collect the users's notes. A markdown file is created and passed to [pandoc](https://pandoc.org/) to create a pdf using the [Eisvogel LaTeX template] (https://github.com/Wandmalfarbe/pandoc-latex-template). There are some rules and guidelines in regards to the structure of the cherrytree file. These will be described in this README in the near future.

## Features
* Collect CVE details automatically
* Add static sections from the by Offsec provided [exam report template](https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf) automatically
* Generate an appendix with all the collected proof contents automatically
* Automatically name, archive and password protect the final file that should be send to Offsec after taking the exam as per the instructions in [this guide](https://support.offensive-security.com/oscp-exam-guide/)

## Credits

* [Eisvogel template](https://github.com/Wandmalfarbe/pandoc-latex-template)
* [Noraj OSCP Exam Report in Markdown](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown) for inspiration
* [Docker image](https://github.com/rstropek/pandoc-latex)

