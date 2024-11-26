import os
import requests
import zipfile
from bs4 import BeautifulSoup
import platform
from circuitbreaker import circuit
import json
import xmltodict
import time
import subprocess
import fnmatch
 
MAX_RETRIES = 5
 
def download_files_cve(import_path):
    url = 'https://nvd.nist.gov/vuln/data-feeds'
    root = 'https://nvd.nist.gov/'
    start_time = time.time()
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.json.zip' in dl and 'nvdcve' in dl
    ]
    download_folder = import_path + "nist/cve/"
    extract_dir = import_path + "nist/cve/"
 
    # Download and Unzip the files
    print('\nUpdating the Database with all the CVE Files...')
    for zip_file in zip_files:
        print("Zip file: ", zip_file)
        full_url = root + zip_file
        zip_file_name = os.path.basename(zip_file)
        download_file_to_path(full_url, download_folder, zip_file_name)
        unzip_files_to_directory(download_folder, extract_dir, zip_file_name)
 
    transform_xml_files_to_json(extract_dir)
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cve','CVE_Items')
    end_time = time.time()
    print(f"\nCVE Files: download completed within { end_time - start_time }\n----------")
 
def download_files_cve_update(tag,import_path):
    url_tag = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{tag}.json.zip"
    file_name = f"nvd_data_{tag}.json.zip"
    response = requests.get(url_tag)
    if response.status_code == 200:
            with open(file_name, 'wb') as file:
                file.write(response.content)
            print(f"\nDownloaded NVD data {tag} to {file_name}")
    download_folder = import_path + "nist/cve/update/"
    extract_dir = import_path + "nist/cve/update/"
 
    # Download and Unzip the files
    print('\nUpdating the Database with the latest CVE Files...')
   
    zip_file_name = os.path.basename(file_name)
    download_file_to_path(url_tag, download_folder, zip_file_name)
    unzip_files_to_directory(download_folder, extract_dir, zip_file_name)
    transform_xml_files_to_json(extract_dir)
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cve','CVE_Items')
 
def download_cve_latest(path):
    start_time = time.time()
    download_files_cve_update('recent',path)
    download_files_cve_update('modified',path)
    end_time = time.time()
    print(f"\nCVE Files: download completed within { end_time - start_time }\n----------")
 
def download_files_cpe(import_path):
    start_time = time.time()
    url = 'https://nvd.nist.gov/vuln/data-feeds'
    root = 'https://nvd.nist.gov/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.json.zip' in dl and 'nvdcpematch' in dl
    ]
    download_folder = import_path + "nist/cpe/"
    extract_dir = import_path + "nist/cpe/"
#
    # Download and Unzip the files
    print('\nUpdating the Database with the latest CPE Files...')
    for zip_file in zip_files:
        full_url = root + zip_file
        zip_file_name = os.path.basename(zip_file)
        # 5 attempts to download and unzip the file correctly
        download_file_to_path(full_url, download_folder, zip_file_name)
        unzip_files_to_directory(download_folder, extract_dir, zip_file_name)
#
    transform_xml_files_to_json(extract_dir)
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cpe','matches')
    end_time = time.time()
    print(f"\nCPE Files: download completed within { end_time - start_time }\n----------")
 
def download_files_cwe(import_path):
    url = 'https://cwe.mitre.org/data/archive.html'
    root = 'https://cwe.mitre.org/'
    start_time = time.time()
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.xml.zip' in dl
    ]
    zip_file = zip_files[0]
    download_folder = import_path + "mitre_cwe/"
    extract_dir = import_path + "mitre_cwe/"
 
    # Download and Unzip the files
    print('\nUpdating the Database with the latest CWE Files...')
    full_url = root + zip_file
    zip_file_name = os.path.basename(zip_file)
 
    # 5 attempts to download and unzip the file correctly
    download_file_to_path(full_url, download_folder, zip_file_name)
    unzip_files_to_directory(download_folder, extract_dir, zip_file_name)
    transform_xml_files_to_json(extract_dir)
    replace_unwanted_string_cwe(extract_dir)
    preprocess_cwe(extract_dir+"cwe.json",extract_dir+"cwe.json")
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'cwe_reference','Weakness_Catalog.External_References.External_Reference')
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'cwe_weakness','Weakness_Catalog.Weaknesses.Weakness')
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'cwe_category','Weakness_Catalog.Categories.Category')
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'cwe_view','Weakness_Catalog.Views.View')
    end_time = time.time()
    print(f"\nCWE Files: download completed within { end_time - start_time }\n----------")
 
def download_files_capec(import_path):
    url = 'https://capec.mitre.org/data/archive.html'
    root = 'https://capec.mitre.org/'
    start_time = time.time()
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    xml_files = [
        dl for dl in all_links if dl and '.xml' in dl
    ]
    xml_file = xml_files[0]
 
    download_folder = import_path + "mitre_capec/"
    extract_dir = import_path + "mitre_capec/"
 
    # Download xml file
    print('\nUpdating the Database with the latest CAPEC Files...')
    full_url = root + xml_file
    zip_file_name = os.path.basename(xml_file)
 
    download_file_to_path(full_url, download_folder, zip_file_name)
    transform_xml_files_to_json(download_folder)
    replace_unwanted_string_capec(download_folder)
    preprocess_capec(extract_dir+"capec.json", extract_dir+"capec.json")
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'capec_reference','Attack_Pattern_Catalog.External_References.External_Reference')
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'capec_attack_pattern','Attack_Pattern_Catalog.Attack_Patterns.Attack_Pattern')
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'capec_category','Attack_Pattern_Catalog.Categories.Category')
    transform_big_json_files_to_multiple_json_files_cwe_capec(extract_dir, 'capec_view','Attack_Pattern_Catalog.Views.View')
    end_time = time.time()
    print(f"\nCAPEC Files: download completed within { end_time - start_time }\n----------")
 
# Define the function that makes the HTTP request with retry
def make_http_request_with_retry(url, retries=0):
    try:
        # Call the function that makes the HTTP request, protected by the circuit breaker
        return download_file_to_path(url)
    except circuit.BreakerOpenError:
        if retries < MAX_RETRIES:
            print(f"Circuit is open. Retrying... Attempt {retries + 1}")
            return make_http_request_with_retry(url, retries=retries + 1)
        else:
            raise RuntimeError("Circuit is open. Max retries reached.")
    except Exception as e:
        if retries < MAX_RETRIES:
            print(f"Error occurred: {e}. Retrying... Attempt {retries + 1}")
            return make_http_request_with_retry(url, retries=retries + 1)
        else:
            raise RuntimeError("Max retries reached. Last error: {}".format(e))
 
def replace_unwanted_string_cwe(path):
    listOfFiles = os.listdir(path)
    pattern = "*.json"
    files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwec"):
                files.append(entry)
                break
    file = path + files[0]
    fin = open(file, "rt")
    flattened_cwe = path + "cwe.json"
    fout = open(flattened_cwe, "wt")
    for line in fin:
        fout.write(line.replace('"@', '"'))
    fin.close()
    os.remove(file)
    fout.close()
 
def flatten_to_string(value):
    if isinstance(value, dict):
        xhtml_content = value.get('xhtml:p',None) or value.get('xhtml:ul',{}).get('xhtml:li',None)
        if xhtml_content is not None:
            if isinstance(xhtml_content, list):
                return ' '.join(flatten_to_string(item)for item in xhtml_content)
            else:
                return str(xhtml_content)
        else:
            return json.dumps(value)
    elif isinstance(value,list):
        return ' '.join(flatten_to_string(v)for v in value)
    else:
        return str(value)
 
def preprocess_cwe(input_filename, output_filename):
    with open(input_filename, 'r', encoding='utf-8') as file:
        data = json.load(file)
 
    for entry in data ['Weakness_Catalog']['Weaknesses']['Weakness']:
        #Process extended_description
        if 'Extended_Description' in entry:
            entry['Extended_Description']= flatten_to_string(entry['Extended_Description'])
       
        if 'Background_Details' in entry and 'Background_Detail' in entry ['Background_Details']:
            entry['Background_Details']['Background_Detail']=flatten_to_string(entry['Background_Details']['Background_Detail'])
       
        if 'Demonstrative_Examples' in entry and 'Demonstrative_Example' in entry['Demonstrative_Examples']:
            examples = entry['Demonstrative_Examples']['Demonstrative_Example']
            for example in examples if isinstance(examples, list) else [examples]:
                if 'Intro_Text' in example:
                    example['Intro_Text']=flatten_to_string(example['Intro_Text'])
                if 'Body_Text' in example:
                    example['Body_Text']=flatten_to_string(example['Body_Text'])
                if 'Example_Code' in example:
                    example['Example_Code']=flatten_to_string(example['Example_Code'])
       
        if 'Detection_Methods' in entry and 'Detection_Method' in entry['Detection_Methods']:
            detections = entry['Detection_Methods']['Detection_Method']
            for detection in detections if isinstance(detections, list) else [detections]:
                if 'Description' in detection:
                    detection['Description']=flatten_to_string(detection['Description'])
                if 'Effectiveness_Notes' in example:
                    detection['Effectiveness_Notes']=flatten_to_string(detection['Effectiveness_Notes'])
       
        if 'Potential_Mitigations' in entry and 'Mitigation' in entry ['Potential_Mitigations']:
            mitigations = entry['Potential_Mitigations']['Mitigation']
            for mitigation in mitigations if isinstance(mitigations, list) else [mitigations]:
                if 'Description' in mitigation:
                    mitigation['Description']=flatten_to_string(mitigation['Description'])
                if 'Effectiveness_Notes' in mitigation:
                    mitigation['Effectiveness_Notes']=flatten_to_string(mitigation['Effectiveness_Notes'])
 
        if 'Common_Consequences' in entry and 'Consequence' in entry['Common_Consequences']:
            consequences = entry['Common_Consequences']['Consequence']
            for consequence in consequences if isinstance(consequences, list) else [consequences]:
                if 'Scope' in consequence and isinstance(consequence['Scope'], dict):
                    consequence['Scope']=flatten_to_string(consequence['Scope'])
                if 'Impact' in consequence and isinstance(consequence['Impact'], dict):
                    consequence['Impact']=flatten_to_string(consequence['Impact'])
   
    for entry in data['Weakness_Catalog']['Views']['View']:
        if 'Objective' in entry:
            entry['Objective']=flatten_to_string(entry['Objective'])
 
    #save the processed data back to a new json file
    with open(output_filename, 'w',encoding='utf-8') as file:
        json.dump(data,file,ensure_ascii=False, indent=4)
 
# Flatten CAPEC Dataset File
def replace_unwanted_string_capec(path):
    listOfFiles = os.listdir(path)
    pattern = "*.json"
    files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("capec"):
                files.append(entry)
                break
    file = path + files[0]
    fin = open(file, "rt")
    flattened_cwe = path + "capec.json"
    fout = open(flattened_cwe, "wt")
    for line in fin:
        fout.write(line.replace('"@', '"').replace('#text', 'text'))
    fin.close()
    fout.close()
    os.remove(file)
 
def preprocess_capec(input_filename, output_filename):
    with open(input_filename, 'r', encoding='utf-8') as file:
        data = json.load(file)
   
    for entry in data['Attack_Pattern_Catalog']['Attack_Patterns']['Attack_Pattern']:
 
        if 'Mitigations' in entry and 'Mitigation' in entry['Mitigations']:
            entry['Mitigations']['Mitigation'] = flatten_to_string(entry['Mitigations']['Mitigation'])
 
        if 'Example_Instances' in entry and 'Example' in entry['Example_Instances']:
            entry['Example_Instances']['Example'] = flatten_to_string(entry['Example_Instances']['Example'])
       
        if 'Description' in entry :
            entry['Description']= flatten_to_string(entry['Description'])
 
        if 'Resources_Required' in entry and 'Resource' in entry['Resources_Required']:
            entry['Resources_Required']['Resource'] = flatten_to_string(entry['Resources_Required']['Resource'])
       
    #save the processed data back to a new json file
    with open(output_filename, 'w',encoding='utf-8') as file:
        json.dump(data,file,ensure_ascii=False, indent=4)
 
# Define the function that makes the HTTP request
@circuit(failure_threshold=10)
def download_file_to_path(url, download_path, file_name):
    print("Download path: ", download_path)
    if not os.path.exists(download_path):
        os.makedirs(download_path, exist_ok=True)
    r = requests.get(url)
    dl_path = os.path.join(download_path, file_name)
    with open(dl_path, 'wb') as file:
        file.write(r.content)
 
def unzip_files_to_directory(zip_path, extract_path, zip_filename):
    try:
        if not os.path.exists(extract_path):
            os.makedirs(extract_path, exist_ok=True)
        z = zipfile.ZipFile(os.path.join(zip_path, zip_filename))
        z.extractall(extract_path)
        print(zip_filename + ' unzipped successfully')
        print('---------')
        z.close()
        current_os = platform.system()
        if (current_os == "Linux" or current_os == "Darwin"):
            file_to_delete = f'{extract_path}' + f'/{zip_filename}'
        elif current_os == "Windows":
            file_to_delete = f'{extract_path}' + f'\\{zip_filename}'
        os.remove(file_to_delete)
    except zipfile.BadZipfile as e:
        print(f"Error while unzipping data : {str(e)} on file: {zip_filename}")
 
def transform_xml_files_to_json(path):
    directory_contents = os.listdir(path)
 
    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".xml") and os.path.isfile(item_path):
            xml_file_to_json(item_path)
            os.remove(item_path)
 
def transform_big_json_files_to_multiple_json_files(path, output_prefix, json_array_path):
    directory_contents = os.listdir(path)
 
    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".json") and os.path.isfile(item_path):
            slice_json_file(item_path, path, output_prefix, 200, json_array_path)
 
def transform_big_json_files_to_multiple_json_files_cwe_capec(path, output_prefix, json_array_path):
    directory_contents = os.listdir(path)
 
    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".json") and os.path.isfile(item_path):
            slice_json_file_cwe_capec(item_path, path, output_prefix, 200, json_array_path)
 
# Convert XML Files to JSON Files
def xml_file_to_json(xmlFile):
    # parse the import folder for xml files
    # open the input xml file and read
    # data in form of python dictionary
    # using xmltodict module
    print(f"Transforming file {xmlFile}")
    if xmlFile.endswith(".xml"):
        with open(xmlFile, 'r', encoding='utf-8') as xml_file:
            data_dict = xmltodict.parse(xml_file.read())
            xml_file.close()
            # generate the object using json.dumps()
            # corresponding to json data
            json_data = json.dumps(data_dict)
            # Write the json data to output
            # json file
            xml_file.close()
        jsonfile = f'{xmlFile}'
        print(jsonfile)
        jsonfile = jsonfile.replace(".xml", ".json")
        print(jsonfile)
        with open(jsonfile, "w") as json_file:
            json_file.write(json_data)
            json_file.close()
 
def flatten_to_string(value):
    if isinstance(value, dict):
        xhtml_content = value.get('xhtml:p',None) or value.get('xhtml:ul',{}).get('xhtml:li',None)
        if xhtml_content is not None:
            if isinstance(xhtml_content, list):
                return ' '.join(flatten_to_string(item)for item in xhtml_content)
            else:
                return str(xhtml_content)
        else:
            return json.dumps(value)
    elif isinstance(value,list):
        return ' '.join(flatten_to_string(v)for v in value)
    else:
        return str(value)


def slice_json_file(input_file, output_path, output_prefix, batch_size, json_array_path):
    with open(input_file, 'r') as f:
        data = json.load(f)
    data_array = select_nested_array_by_path(data, json_array_path)
    length = len(data_array)
 
    if not os.path.exists(os.path.join(output_path, "splitted")):
        os.makedirs(os.path.join(output_path, "splitted"), exist_ok=True)
 
    for i in range(0, length, batch_size):
        batch = data_array[i:i+batch_size]
        output_file = f"{output_path}/splitted/{output_prefix}_output_file_{i//batch_size + 1}.json"
        with open(output_file, 'w') as f_out:
            json.dump(batch, f_out, indent=4)
    os.remove(input_file)
 
def slice_json_file_cwe_capec(input_file, output_path, output_prefix, batch_size, json_array_path):
    with open(input_file, 'r') as f:
        data = json.load(f)
    data_array = select_nested_array_by_path(data, json_array_path)
    length = len(data_array)
 
    if not os.path.exists(os.path.join(output_path, "splitted")):
        os.makedirs(os.path.join(output_path, "splitted"), exist_ok=True)
 
    for i in range(0, length, batch_size):
        batch = data_array[i:i+batch_size]
        output_file = f"{output_path}/splitted/{output_prefix}_output_file_{i//batch_size + 1}.json"
        with open(output_file, 'w') as f_out:
            json.dump(batch, f_out, indent=4)
 
def select_nested_array_by_path(json_data, path):
    parsed_json = json_data
    keys = path.split('.')
 
    for key in keys:
        if key in parsed_json:
            parsed_json = parsed_json[key]
        else:
            return None
 
    return parsed_json
 
def run_dos2unix(file):
    try:
        dos2unix_command = f'dos2unix {file}'
        print("Executing command:", dos2unix_command)
 
        process = subprocess.run(['dos2unix', file], capture_output=True, text=True, check=True)
        if process.returncode == 0:
            print(f"File {file} transformed to unix format")
        else:
            raise RuntimeError(f"Error running dos2unix command: {process.stderr.strip()}")
    except FileNotFoundError:
        raise RuntimeError("dos2unix command not found. Make sure jq is installed on your system.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error running dos2unix command. Make sure dos2unix is installed and check your file. Error: {e}")