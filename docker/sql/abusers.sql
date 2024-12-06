CREATE TABLE abuse_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATETIME,
    ip VARCHAR(15),
    abuse VARCHAR(50),
    path TEXT,
    body TEXT,
    headers JSON
);