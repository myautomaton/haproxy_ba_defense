import requests
import os
import yaml
from urllib.parse import urlencode

# Flatten the dictionary for URL parameters
def flatten_dict(d, parent_key=''):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(flatten_dict(item, f"{new_key}[{i}]").items())
                else:
                    items.append((f"{new_key}[{i}]", item))
        elif isinstance(v, dict):
            items.extend(flatten_dict(v, new_key).items())
        else:
            items.append((new_key, v))
    return dict(items)

def read_yaml_files(directory_path):
    # Dictionary to hold the contents of each YAML file
    yaml_contents = {}

    # Loop through all files in the directory
    for filename in os.listdir(directory_path):
        # Check if the file has a .yaml or .yml extension
        if filename.endswith('.yaml') or filename.endswith('.yml'):
            file_path = os.path.join(directory_path, filename)
            try:
                # Open and read the YAML file
                with open(file_path, 'r') as file:
                    yaml_data = yaml.safe_load(file)
                    yaml_contents[filename] = yaml_data
            except yaml.YAMLError as e:
                print(f"Error parsing {filename}: {e}")
            except Exception as e:
                print(f"Error reading {filename}: {e}")
    
    return yaml_contents



# Directory containing YAML files
directory_path = "/opt/abuse"  # Replace with your directory path

try:

    # Read all YAML files in the directory
    all_yaml_data = read_yaml_files(directory_path)

    # Print out the contents of each YAML file
    for filename, content in all_yaml_data.items():

        # Flatten the data dictionary for URL encoding
        query_params = flatten_dict(content)

        # API endpoint URL (replace with the actual endpoint)
        url = "http://demo:demo@10.201.0.40:8080/run/   /"  # Replace with actual API endpoint

        # Send GET request with URL-encoded query parameters
        response = requests.get(url, params=query_params)

        # Check for a successful response
        response.raise_for_status()
        print("Data sent successfully:", response.json())
        

except requests.exceptions.RequestException as e:
    print(f"Error sending data to the API: {e}")


