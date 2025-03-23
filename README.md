# Threat Hunter AI

**Threat Hunter AI** is an autonomous cybersecurity agent that scans system logs, detects potential threats, and maps attack paths using cutting-edge AI techniques. This project leverages generative AI, reinforcement learning, and graph-based analysis to enhance threat detection and response in modern Security Operations Centers (SOCs).

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [License](#license)

## Overview

In today’s evolving cybersecurity landscape, organizations need proactive and intelligent threat detection systems. Threat Hunter AI autonomously ingests logs, uses GPT-based agents for log summarization and threat correlation, trains a reinforcement learning (RL) agent to refine its threat-hunting policy, and employs graph-based reasoning (with Neo4j) to map and analyze potential attack paths.

## Features

- **Log Ingestion & Analysis:**  
  Integrates with the ELK Stack and Suricata to collect and parse system logs.

- **GPT-Based Summarization:**  
  Uses LangChain and GPT-4 to summarize logs and correlate them with known threat intelligence.

- **Reinforcement Learning Agent:**  
  Implements a PPO (Proximal Policy Optimization) based agent that learns to detect and respond to threats by training on historical incident patterns.

- **Graph-Based Attack Analysis:**  
  Utilizes Neo4j to build and analyze attack graphs, mapping potential paths an attacker could exploit.

## Tech Stack

- **Programming Language:** Python
- **AI Frameworks:**  
  - OpenAI GPT-4 via LangChain  
  - Reinforcement Learning (PPO)
- **Logging & IDS:**  
  - Elastic Stack (ELK)  
  - Suricata
- **Graph Database:** Neo4j
- **Deployment:** Deployed via Replit

## Architecture

The project is organized into modular components:

- **Log Analyzer:**  
  Ingests logs from ELK and Suricata, preprocesses the data, and feeds it to the GPT summarization agent.

- **Summarization Agent:**  
  Uses GPT-4 to analyze and summarize log data, highlighting anomalies and potential threats.

- **RL Threat Hunter:**  
  Trains using historical threat data to learn adaptive threat detection and mitigation strategies.

- **Attack Graph Analyzer:**  
  Uses Neo4j to create and traverse attack graphs, providing insight into potential threat vectors.

## Installation & Setup

### Prerequisites

- Python 3.8+
- [Git](https://git-scm.com/)
- [pip](https://pip.pypa.io/)

### Clone the Repository

```bash
git clone https://github.com/AhmedKhal18/threat-hunter-ai.git
cd threat-hunter-ai
```
## Install Dependencies
Make sure you have a virtual environment set up, then install the required packages:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install -r requirements.txt
```
## Configuration
Ensure you have the necessary API keys and secrets set as environment variables. For example:
```bash
export OPENAI_API_KEY='your_openai_api_key'
export SESSION_SECRET='your_session_secret'
```
## Usage
After installation, you can start the application by running:
```bash
python main.py
```
The application starts a web server (configured to run on port 5000 by default) that handles log ingestion, summarization, and threat detection. Adjust the main.py file as needed for your environment.

## Deployment
This project is deployed on Replit. The deployment is configured to use:

vCPUs: 4

RAM: 8 GiB

Run Command:
For example, if using FastAPI:
```bash
gunicorn main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:5000
```
The deployed app can be accessed at:
https://threat-hunter-ai-ahmedkhal18.replit.app

Ensure that environment secrets (like OPENAI_API_KEY and SESSION_SECRET) are securely managed via Replit’s Secrets Manager.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your improvements. For major changes, please open an issue first to discuss what you would like to change.

## License
This project is licensed under the MIT License.

For more information or any questions, please open an issue or contact AhmedKhal18.
