
# VTFlaskScan


VTFlaskScan is a lightweight web application built with Flask that integrates with the VirusTotal API to scan files or potential security threats. It provides a light interface to files items for scanning and view results in a simplified manner.


## Getting Started
Python is required for this application to run and needs to be installed and a guide on how to do so can be found [here](https://realpython.com/installing-python/).

Flask is required as well and can (usually) be installed with:

``pip install flask`` or ```python -m pip install flask```,

Additionally you'll need an API key from VirusTotal. You can get one by signing up to the VirusTotal Communtity.

Documentation on how to obtain an API key can be found [here](https://support.virustotal.com/hc/en-us/articles/115002100149-API). After getting the key make sure to add the API-key in app.py by changing:
```
API_KEY = "your-api-key-here"
```

## Installation

- Clone the repository:
```bash
git clone https://github.com/taha-sh/VTFlaskScan.git
cd VTFlaskScan
```
- Install Flask if you haven't already:
```pip install flask```

- Setup the Flask environment:

For UNIX-systems (Linux, MacOS):
```
export FLASK_APP=app.py
export FLASK_ENV=development
```
For Windows users:
```
set FLASK_APP=app.py
set FLASK_ENV=development
```
- Run the application:
```
flask run
```
The server should start, typically on http://127.0.0.1:5000/.

