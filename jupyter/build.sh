#!/usr/bin/env bash

# Définir le chemin du fichier de log
LOGFILE="build.log"

# Démarrer la journalisation avec 'tee' pour rediriger la sortie vers la console et le fichier log
{

	# Vérifier si le fichier existe
	if [[ -f "$LOGFILE" ]]; then
	  echo "Le fichier $FICHIER existe, suppression en cours..."
	  rm "$LOGFILE"
	  echo "Fichier de log supprimé."
	else
	  echo "Le fichier $LOGFILE n'existe pas."
	fi

	echo "Pulling ollama"
	docker pull ollama/ollama:latest

	echo "Pulling ollama hmi"
	docker pull ghcr.io/open-webui/open-webui:main

	echo "Pulling jupyter datascience-notebook"
	docker pull quay.io/jupyter/datascience-notebook:ubuntu-24.04

	echo "Pulling neo4j"
	docker pull neo4j:5.23-community-bullseye

	echo "Building l_jupyter:V1"
	#docker build --no-cache -f Dockerfile -t "l_jupyter:V1" .
	docker build -f Dockerfile -t "l_jupyter:V1" .
	echo "Build done"
	
} 2>&1 | tee -a "$LOGFILE"