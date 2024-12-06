import requests
import yaml

# API endpoint URL (replace with the actual endpoint)
url = "https://api.example.com/abuse_log"  # Replace with the actual endpoint

try:
    # Send a GET request to the API endpoint
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for unsuccessful requests

    # Parse the YAML response
    data = yaml.safe_load(response.text)

    # Display the parsed data
    print("Fetched YAML Data:")
    print(yaml.dump(data, default_flow_style=False))

except requests.exceptions.RequestException as e:
    print(f"Error fetching data from the API: {e}")
except yaml.YAMLError as e:
    print(f"Error parsing YAML data: {e}")