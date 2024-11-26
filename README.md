# Cybersecurity Hackathon Sandbox

Welcome to the Cybersecurity Hackathon Sandbox repository! This repository provides a Docker-based testing environment for students participating in the hackathon. The goal of the hackathon is to improve data ingestion and storage related to cybersecurity topics to enhance AI responses using Retrieval-Augmented Generation (RAG) technology.

## Hackathon Objective

The main objective of this hackathon is to explore and develop methods to improve the ingestion and storage of cybersecurity data. Participants will work on enhancing AI responses on cybersecurity topics using RAG technology. The specific challenge is: **"How to improve the ingestion and storage of data specifically related to cybersecurity topics to enhance AI responses (and the information's traceability) using RAG technology?"**

## Docker Environment

This repository includes a Docker Compose setup that provides a sandbox environment with the following services:

### Services

#### Jupyter

- **Description**: This service provides a Jupyter Notebook environment for data analysis and experimentation. It allows participants to interactively work with data, run code, and visualize results. The Jupyter container is configured with various volumes to persist data and modules, and it is accessible via port 8888. (Access token : "easy")

#### Neo4j

- **Description**: This service runs a Neo4j graph database, which is used for storing and querying cybersecurity data. Neo4j is particularly suited for handling complex relationships and structures within the data. The container is configured with specific memory and performance settings to handle large datasets and is accessible via ports 7474 (HTTP) and 7687 (Bolt). (credentials : neo4j/strongPassword1)

#### Ollama

- **Description**: This service hosts the Ollama AI model, which is used for AI interactions and processing. It is designed to keep the AI model running and accessible for extended periods, ensuring that participants can reliably interact with the AI. The service is accessible via ports 11434 and 7869.

#### Ollama WebUI

- **Description**: This service provides a web-based user interface for interacting with the Ollama AI model. It allows participants to easily access and use the AI capabilities through a browser. The WebUI is configured to connect to the Ollama service and is accessible via port 8080.

## Use Cases

The following use cases are provided as examples and sources of inspiration to help students understand the needs and avoid starting from scratch. These use cases are provided as functional Jupyter notebooks(located in "\data_jupyter\work") :

1. **Downloading and Ingesting CVE Descriptions**:
   - Download and ingest CVE descriptions from the NVD database into a knowledge graph using a predefined schema.
   - Utilize RAG technology to enhance AI responses.

2. **Ingesting PDF Content into a Vector Database**:
   - Ingest PDF content into a vector database.
   - Utilize RAG technology to enhance AI responses.

3. **Automated Knowledge Graph Inference**:
   - Perform automated inference of a knowledge graph from raw text (e.g., from PDFs, websites).
   - Utilize RAG technology to enhance AI responses.

## Prerequisites

Before starting, ensure you have the following installed:

- **Docker Desktop** (or an equivalent software like Rancher Desktop or Podman Desktop)
  
- The necessary **LLM models** used in the notebooks, which can be **downloaded via the Ollama WebUI**. This step is crucial for the notebooks to function correctly.

This environment has been successfully tested on windows 11 (with the last version of rancher-desktop) and on OSX 15 (with the last version of docker-desktop).

We hope this environment and these examples showing different strategies will inspire you to develop innovative solutions to improve cybersecurity data handling and AI response capabilities. 

Good luck and happy hacking!

## Getting Started

To get started,  run the following Docker command to start the environment:

to download & build images : (could be quite long the first build time)

```sh
./setup.sh
```

to start:

```sh
docker-compose up -d
```

to stop:

```sh
docker-compose down
```