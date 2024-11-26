import os
import time
import fnmatch
from neo4j import exceptions, GraphDatabase
 
driver = GraphDatabase.driver("neo4j://neo4j:7687", auth=("neo4j","strongPassword1"))
root_import_path = "/var/lib/neo4j/import"

# Variable globale pour définir la taille des batchs
BATCH_SIZE = 15  # Taille du batch


def create_indexes():
    # Liste des requêtes Cypher pour créer les index
    index_queries = [
        "CREATE INDEX IF NOT EXISTS FOR (c:CWE) ON (c.Name);",
        "CREATE INDEX IF NOT EXISTS FOR (c:CAPEC) ON (c.Name);",
        "CREATE INDEX IF NOT EXISTS FOR (c:CVE) ON (c.Name);",
        "CREATE INDEX IF NOT EXISTS FOR (c:CPE) ON (c.uri);",
        "CREATE INDEX IF NOT EXISTS FOR (r:External_Reference_CWE) ON (r.Reference_ID);",
        "CREATE INDEX IF NOT EXISTS FOR (r:External_Reference_CAPEC) ON (r.Reference_ID);",
        "CREATE INDEX IF NOT EXISTS FOR (c:Consequence) ON (c.Scope);",
        "CREATE INDEX IF NOT EXISTS FOR (m:Mitigation) ON (m.Description);",
        "CREATE INDEX IF NOT EXISTS FOR (d:Detection_Method) ON (d.Method);"
    ]
    
    try:
        # Ouvrir une session Neo4j
        with driver.session() as session:
            for query in index_queries:
                try:
                    # Exécuter chaque requête Cypher pour créer les index
                    session.run(query)
                    print(f"Index created successfully: {query}")
                except exceptions.ClientError as e:
                    print(f"Error creating index: {query}, Error: {e}")
    except exceptions.DriverError as e:
        print(f"DriverError: {e}")
    finally:
        # Fermer la connexion Neo4j
        driver.close()

# Define which Dataset and Cypher files will be imported on CVE Insertion
def files_to_insert_cve(import_path):
    listOfFiles = os.listdir(import_path)
    path = "nist/cve/splitted/"  # Répertoire correct pour les fichiers
    pattern = "*.json"
    cve_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cve_output"):
                # Ajouter l'URL du fichier, en utilisant file:// pour que Neo4j puisse accéder aux fichiers
                cve_files.append(f"file:///{os.path.join(root_import_path, path + entry)}")
    return cve_files

# Cypher Query to insert a batch of CVE files using apoc.load.json
def query_cve_batch(batch_files):
    start_time = time.time()

    # Lire la requête Cypher depuis le fichier CVEs.cypher
    with open("libs/CypherScripts/CVEs.cypher", "r") as cves_cypher_file:
        query = cves_cypher_file.read()

    try:
        with driver.session() as session:
            # Passer la liste des fichiers comme paramètre à $cveFilesToImport
            result = session.run(query, {"cveFilesToImport": batch_files})  
            summary = result.consume()  # Utilisation de consume() pour obtenir un résumé des transactions
            
            # Afficher les détails du résumé
            print("Query executed successfully.")
            print(f"- Counters: {summary.counters}")
            print(f"- Time to result: {summary.result_available_after} ms")
            print(f"- Time to consume: {summary.result_consumed_after} ms")
            #print(f"- Query: {summary.query}")

    except exceptions.ClientError as e:
        print(f"ClientError: {e}", flush=True)
    except exceptions.DriverError as e:
        print(f"DriverError: {e}", flush=True)
    except Exception as e:
        print(f"An error occurred: {e}", flush=True)

    end_time = time.time()
    print(f"\nBatch of CVE Files: {batch_files} insertion completed within {end_time - start_time} seconds.\n----------", flush=True)

# Configure CVE Files and CVE Cypher Script for insertion using batch processing
def cve_insertion(import_path):
    try:
        print("\nInserting CVE Files to Database...", flush=True)
        files = files_to_insert_cve(import_path)

        # Calcul du nombre total de batchs
        total_batches = (len(files) + BATCH_SIZE - 1) // BATCH_SIZE  # Calcul du nombre de batchs
        
        print(f"Total number of batches: {total_batches}, Batch size: {BATCH_SIZE} files per batch\n", flush=True)

        # Créer des batchs
        for i in range(0, len(files), BATCH_SIZE):
            batch_number = i // BATCH_SIZE + 1  # Numéro du batch actuel
            batch_files = files[i:i + BATCH_SIZE]  # Prendre les fichiers batch par batch
            print(f"Inserting batch {batch_number}/{total_batches} with {len(batch_files)} files...", flush=True)
            query_cve_batch(batch_files)  # Passer la liste complète des fichiers du batch

    except exceptions.DriverError as e:
        print(f"DriverError: {e}", flush=True)





# Define which Dataset and Cypher files will be imported on CPE Insertion
def files_to_insert_cpe(import_path):
    listOfFiles = os.listdir(import_path)
    path = "nist/cpe/splitted/"  # Répertoire correct pour les fichiers
    pattern = "*.json"
    cpe_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cpe_output"):
                # Ajouter l'URL du fichier, en utilisant file:// pour que Neo4j puisse accéder aux fichiers
                cpe_files.append(f"file:///{os.path.join(root_import_path, path + entry)}")
    return cpe_files

# Cypher Query to insert a batch of CPE files using apoc.load.json
def query_cpe_batch(batch_files):
    start_time = time.time()

    # Lire le script Cypher depuis le fichier CPEs.cypher
    with open("libs/CypherScripts/CPEs.cypher", "r") as cpes_cypher_file:
        query = cpes_cypher_file.read()

    try:
        with driver.session() as session:
            # Passer la liste des fichiers comme paramètre à $cpeFilesToImport
            result = session.run(query, {"cpeFilesToImport": batch_files})  
            summary = result.consume()  # Utilisation de consume() pour obtenir un résumé des transactions
            
            # Afficher les détails du résumé
            print("Query executed successfully.")
            print(f"- Counters: {summary.counters}")
            print(f"- Time to result: {summary.result_available_after} ms")
            print(f"- Time to consume: {summary.result_consumed_after} ms")
            #print(f"- Query: {summary.query}")

    except exceptions.ClientError as e:
        print(f"ClientError: {e}", flush=True)
    except exceptions.DriverError as e:
        print(f"DriverError: {e}", flush=True)
    except Exception as e:
        print(f"An error occurred: {e}", flush=True)

    end_time = time.time()
    print(f"\nBatch of CPE Files: {batch_files} insertion completed within {end_time - start_time} seconds.\n----------", flush=True)

# Configure CPE Files and CPE Cypher Script for insertion using batch processing
def cpe_insertion(import_path):
    try:
        print("\nInserting CPE Files to Database...", flush=True)
        files = files_to_insert_cpe(import_path)

        # Calcul du nombre total de batchs
        total_batches = (len(files) + BATCH_SIZE - 1) // BATCH_SIZE  # Calcul du nombre de batchs
        
        print(f"Total number of batches: {total_batches}, Batch size: {BATCH_SIZE} files per batch\n", flush=True)

        # Créer des batchs
        for i in range(0, len(files), BATCH_SIZE):
            batch_number = i // BATCH_SIZE + 1  # Numéro du batch actuel
            batch_files = files[i:i + BATCH_SIZE]  # Prendre les fichiers batch par batch
            print(f"Inserting batch {batch_number}/{total_batches} with {len(batch_files)} files...", flush=True)
            query_cpe_batch(batch_files)  # Passer la liste complète des fichiers du batch

    except exceptions.DriverError as e:
        print(f"DriverError: {e}", flush=True)






def query_cwe_reference_script(file):
        start_time = time.time()
        cwes_cypher_file = open("libs/CypherScripts/CWEs_reference.cypher", "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweReferenceFilesToImport', f"'{file}'")
 
        try:
            with driver.session() as session:
                session.run(query)
        except exceptions.ClientError as e:
            print(f"ClientError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
        end_time = time.time()
        print(f"\nCWE Files: { file } insertion completed within { end_time - start_time }\n----------")
 
# Cypher Query to insert CWE weakness Cypher Script
def query_cwe_weakness_script(file):
    start_time = time.time()
    cwes_cypher_file = open("libs/CypherScripts/CWEs_weakness.cypher", "r")
    query = cwes_cypher_file.read()
    query = query.replace('cweWeaknessFilesToImport', f"'{file}'")
    try:
        with driver.session() as session:
            session.run(query)
    except exceptions.ClientError as e:
        print(f"ClientError: {e}")
    except exceptions.DriverError as e:
        print(f"DriverError: {e}")
    except Exception as e:
        # Handle other exceptions
        print(f"An error occurred: {e}")
    end_time = time.time()
    print(f"\nCWE Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Cypher Query to insert CWE category Cypher Script
def query_cwe_category_script(file):
    start_time = time.time()
    cwes_cypher_file = open("libs/CypherScripts/CWEs_category.cypher", "r")
    query = cwes_cypher_file.read()
    query = query.replace('cweCategoryFilesToImport', f"'{file}'")
 
    try:
        with driver.session() as session:
            session.run(query)
    except exceptions.ClientError as e:
        print(f"ClientError: {e}")
    except exceptions.DriverError as e:
        print(f"DriverError: {e}")
    except Exception as e:
        # Handle other exceptions
        print(f"An error occurred: {e}")
    end_time = time.time()
    print(f"\nCWE Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Cypher Query to insert CWE view Cypher Script
def query_cwe_view_script(file):
    start_time = time.time()
    cwes_cypher_file = open("libs/CypherScripts/CWEs_view.cypher", "r")
    query = cwes_cypher_file.read()
    query = query.replace('cweViewFilesToImport', f"'{file}'")
 
    try:
        with driver.session() as session:
            session.run(query)
    except exceptions.ClientError as e:
        print(f"ClientError: {e}")
    except exceptions.DriverError as e:
        print(f"DriverError: {e}")
    except Exception as e:
        # Handle other exceptions
        print(f"An error occurred: {e}")
    end_time = time.time()
    print(f"\nCWE Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Configure CWE Files and CWE Cypher Script for insertion
def cwe_insertion(import_path):
    print("\nInserting CWE Files to Database...")
    files = files_to_insert_cwe_reference(import_path)
    for f in files:
        print('Inserting ' + f)
        query_cwe_reference_script(f)
 
    files = files_to_insert_cwe_weakness(import_path)
    for f in files:
        print('Inserting ' + f)
        query_cwe_weakness_script(f)
 
    files = files_to_insert_cwe_category(import_path)
    for f in files:
        print('Inserting ' + f)
        query_cwe_category_script(f)
 
    files = files_to_insert_cwe_view(import_path)
    for f in files:
        print('Inserting ' + f)
        query_cwe_view_script(f)
 
    # Define which Dataset and Cypher files will be imported on CWE reference Insertion
def files_to_insert_cwe_reference(import_path):
    listOfFiles = os.listdir(import_path)
    path = "import/"+import_path
    pattern = "*.json"
 
    reference_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwe_reference"):
                reference_files.append(path+entry)
            else:
                continue
    return reference_files
 
    # Define which Dataset and Cypher files will be imported on CWE weakness Insertion
def files_to_insert_cwe_weakness(import_path):
    listOfFiles = os.listdir(import_path)
    path = "import/"+import_path
    pattern = "*.json"
    weakness_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwe_weakness"):
                weakness_files.append(path+entry)
            else:
                continue
 
    return weakness_files
 
    # Define which Dataset and Cypher files will be imported on CWE category Insertion
def files_to_insert_cwe_category(import_path):
    listOfFiles = os.listdir(import_path)
    path = "import/"+import_path
    pattern = "*.json"
    category_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwe_category"):
                category_files.append(path+entry)
            else:
                continue
 
    return category_files
 
    # Define which Dataset and Cypher files will be imported on CWE view Insertion
def files_to_insert_cwe_view(import_path):
    listOfFiles = os.listdir(import_path)
    path = "import/"+import_path
    pattern = "*.json"
    view_files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwe_view"):
                view_files.append(path+entry)
            else:
                continue
 
    return view_files
def query_capec_reference_script(file):
        start_time = time.time()
        capecs_cypher_file = open("libs/CypherScripts/CAPECs_reference.cypher", "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecReferenceFilesToImport', f"'{file}'")
        try:
            with driver.session() as session:
                session.run(query)
        except exceptions.ClientError as e:
            print(f"ClientError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
        end_time = time.time()
        print(f"\nCAPEC Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Cypher Query to insert CAPEC attack Cypher Script
def query_capec_attack_script(file):
        start_time = time.time()
        capecs_cypher_file = open("libs/CypherScripts/CAPECs_attack.cypher", "r")
        query = capecs_cypher_file.read()
 
        query = query.replace('capecAttackFilesToImport', f"'{file}'")
        try:
            with driver.session() as session:
                session.run(query)
        except exceptions.ClientError as e:
            print(f"ClientError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
        end_time = time.time()
        print(f"\nCAPEC Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Cypher Query to insert CAPEC category Cypher Script
def query_capec_category_script(file):
        start_time = time.time()
        capecs_cypher_file = open("libs/CypherScripts/CAPECs_category.cypher", "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecCategoryFilesToImport', f"'{file}'")
 
        try:
            with driver.session() as session:
                session.run(query)
        except exceptions.ClientError as e:
            print(f"ClientError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
        end_time = time.time()
        print(f"\nCAPEC Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Cypher Query to insert CAPEC view Cypher Script
def query_capec_view_script(file):
        start_time = time.time()
        capecs_cypher_file = open("libs/CypherScripts/CAPECs_view.cypher", "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecViewFilesToImport', f"'{file}'")
 
        try:
            with driver.session() as session:
                session.run(query)
        except exceptions.ClientError as e:
            print(f"ClientError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
        end_time = time.time()
        print(f"\nCAPEC Files: { file } insertion completed within { end_time - start_time }\n----------")
 
    # Configure CAPEC Files and CAPEC Cypher Script for insertion
def capec_insertion(import_path):
        print("\nInserting CAPEC Files to Database...")
        files = files_to_insert_capec_reference(import_path)
        for f in files:
            print('Inserting ' + f)
            query_capec_reference_script(f)
 
        files = files_to_insert_capec_attack(import_path)
        for f in files:
            print('Inserting ' + f)
            query_capec_attack_script(f)
 
        files = files_to_insert_capec_category(import_path)
        for f in files:
            print('Inserting ' + f)
            query_capec_category_script(f)
 
        files = files_to_insert_capec_view(import_path)
        for f in files:
            print('Inserting ' + f)
            query_capec_view_script(f)
 
    # Define which Dataset and Cypher files will be imported on CAPEC refrence Insertion
def files_to_insert_capec_reference(import_path):
        listOfFiles = os.listdir(import_path)
        path = "import/"+import_path
        pattern = "*.json"
        reference_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_reference"):
                    reference_files.append(path + entry)
                else:
                    continue
 
        return reference_files
 
    # Define which Dataset and Cypher files will be imported on CAPEC attack Insertion
def files_to_insert_capec_attack(import_path):
        listOfFiles = os.listdir(import_path)
        path = "import/"+import_path
        pattern = "*.json"
        attack_pattern_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_attack_pattern"):
                    attack_pattern_files.append(path + entry)
                else:
                    continue
 
        return attack_pattern_files
 
    # Define which Dataset and Cypher files will be imported on CAPEC category Insertion
def files_to_insert_capec_category(import_path):
        listOfFiles = os.listdir(import_path)
        path = "import/"+import_path
        pattern = "*.json"
        category_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_category"):
                    category_files.append(path + entry)
                else:
                    continue
 
        return category_files
 
    # Define which Dataset and Cypher files will be imported on CAPEC view Insertion
def files_to_insert_capec_view(import_path):
        listOfFiles = os.listdir(import_path)
        path = "import/"+import_path
        pattern = "*.json"
        view_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_view"):
                    view_files.append(path + entry)
                else:
                    continue
 
        return view_files
 