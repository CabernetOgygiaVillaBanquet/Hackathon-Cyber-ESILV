#!/usr/bin/env bash

# Définir le chemin du fichier de log
LOGFILE="setup.log"

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

	# Récupérer toutes les images dont le nom commence par 'l_'
	images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep '^l_')

	# Vérifier si des images correspondantes existent
	if [[ -n "$images" ]]; then
	  echo "Les images suivantes vont être supprimées :"
	  echo "$images"
  
	  # Supprimer chaque image correspondante
	  for image in $images; do
	    docker rmi -f "$image"
	    echo "Image $image supprimée."
	  done
	else
	  echo "Aucune image commençant par 'l_' n'a été trouvée."
	fi

	cd jupyter
	bash build.sh
	cd ..

} 2>&1 | tee -a "$LOGFILE"