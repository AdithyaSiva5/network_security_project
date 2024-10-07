# Network Security Project

## Overview
This project focuses on enhancing network security by providing two core functionalities:
- **Malware Detection** using ClamAV to scan files for malicious content.
- **Port Scanning** using `nmap` to detect open or vulnerable ports on the network.

The project integrates Flask for the web interface, MongoDB for storing reports, and supports IP address validation, real-time malware scanning, and IP scanning.

## Features
- **IP Address Scanning**: 
  - Scans a target IP for open ports using `nmap`.
  - Saves the scan results to MongoDB for further analysis.
  - IP validation ensures that only valid IP addresses are scanned.
  
- **Malware Scanning**: 
  - Allows users to upload files for scanning using ClamAV.
  - Results (infected/clean) are stored in MongoDB.
  
- **Report Management**: 
  - Provides paginated access to stored reports via an API.
  - Filter reports by type (IP scans, malware scans), time (last 24h, 7d, 30d), and status (infected, clean, failed).

## Technologies Used
- **Flask**: Backend web framework to handle requests and render templates.
- **MongoDB**: NoSQL database used to store scan reports.
- **nmap**: Network scanning tool used for scanning ports.
- **ClamAV**: Malware detection tool integrated with the application for scanning files.
- **pymongo**: Python library for MongoDB interaction.
- **pyclamd**: Python library for interfacing with ClamAV for malware scanning.
- **HTML & Jinja**: For templating the frontend.

## Setup and Installation

### Prerequisites
- Python 3.x
- MongoDB (running instance)
- ClamAV (running on `localhost:3310`)

### Install Dependencies
1. Clone the repository:
   ```bash
   git clone https://github.com/AdithyaSiva5/network_security_project.git
   cd network_security_project
