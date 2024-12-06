import mysql.connector
import yaml
import json

# Database configuration (replace with your own settings)
db_config = {
    'user': 'your_username',
    'password': 'your_password',
    'host': 'your_host',
    'database': 'your_database'
}

# Connect to the MySQL database
try:
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)  # Use dictionary=True to get rows as dictionaries

    # Fetch all rows from the abuse_log table
    query = "SELECT date, ip, abuse, path, body, headers FROM abuse_log"
    cursor.execute(query)
    rows = cursor.fetchall()

    # Process and format the rows for YAML
    yaml_data = []
    for row in rows:
        # Convert JSON headers to Python dictionary
        if row['headers']:
            row['headers'] = json.loads(row['headers'])
        yaml_data.append({'abuser': row})

    # Write the data to a YAML file
    with open('abuse_log.yaml', 'w') as file:
        yaml.dump(yaml_data, file, default_flow_style=False)

    print("Data exported successfully to abuse_log.yaml")

except mysql.connector.Error as err:
    print("Error: {}".format(err))

finally:
    # Close the connection
    if connection.is_connected():
        cursor.close()
        connection.close()