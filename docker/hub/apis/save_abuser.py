
print("Save to db")



# import yaml
# import mysql.connector
# import json
# from datetime import datetime

# # Database configuration (replace with your own settings)
# db_config = {
#     'user': 'root',
#     'password': '1234',
#     'host': '10.201.0.15',
#     'database': 'patronum'
# }

# # Parse the YAML file
# with open('/tmp/output.yaml', 'r') as file:
#     data = yaml.safe_load(file)

# # Extract data
# abuse_date = datetime.strptime(data['abuser']['date'], '%Y-%m-%d %H:%M:%S')
# ip = data['abuser']['ip']
# abuse_type = data['abuser']['abuse']
# path = data['abuser'].get('path', '')
# body = data['abuser'].get('body', '')

# # Convert headers list to JSON format
# headers = {header_key: header_value for header in data['abuser']['headers'] for header_key, header_value in header.items()}
# headers_json = json.dumps(headers)

# # Insert into MySQL
# try:
#     connection = mysql.connector.connect(**db_config)
#     cursor = connection.cursor()

#     # SQL query to insert data
#     sql = """
#     INSERT INTO abuse_log (date, ip, abuse, path, body, headers)
#     VALUES (%s, %s, %s, %s, %s, %s)
#     """
#     cursor.execute(sql, (abuse_date, ip, abuse_type, path, body, headers_json))

#     # Commit the transaction
#     connection.commit()
#     print("Data inserted successfully.")

# except mysql.connector.Error as err:
#     print("Error: {}".format(err))

# finally:
#     # Close the connection
#     if connection.is_connected():
#         cursor.close()
#         connection.close()