DROP TABLE code IF EXISTS;
DROP TABLE token IF EXISTS;
DROP TABLE user IF EXISTS;
DROP TABLE client IF EXISTS;

CREATE TABLE IF NOT EXISTS user (id int AUTO_INCREMENT PRIMARY KEY, username VARCHAR (255), secret VARCHAR(255));
CREATE TABLE IF NOT EXISTS client (id int AUTO_INCREMENT PRIMARY KEY, secret VARCHAR (255), name VARCHAR(255), uri VARCHAR(255), redirect_uri VARCHAR(255), grant_type VARCHAR(255), response_type VARCHAR(255), tokenEndpointAuthMethod VARCHAR(255), scope VARCHAR(255));

CREATE TABLE IF NOT EXISTS code (id int AUTO_INCREMENT, content VARCHAR(255),expiry TIMESTAMP, scope VARCHAR(255),PRIMARY KEY (id), user_id int, FOREIGN KEY (user_id) REFERENCES user(id), code_challenge_method VARCHAR(255), code_challenge VARCHAR(255), client_id VARCHAR(255));
CREATE TABLE IF NOT EXISTS token (id int AUTO_INCREMENT, content VARCHAR(255), expiry TIMESTAMP, scope VARCHAR(255), PRIMARY KEY (id), user_id int, FOREIGN KEY (user_id) REFERENCES user(id), client_id int, FOREIGN KEY (client_id) REFERENCES client(id));

INSERT INTO user (username, secret) VALUES ('alice', 'secure');
INSERT INTO client (id, secret, name, uri, redirect_uri, grant_type, response_type, tokenEndpointAuthMethod, scope) VALUES ('1', 'sec123', 'default_client', 'http://localhost:3000', 'http://localhost:3000/redirect', 'authorization_code', 'code', 'secret_basic', 'read write')