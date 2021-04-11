DROP TABLE code IF EXISTS;
DROP TABLE token IF EXISTS;
DROP TABLE user IF EXISTS;

CREATE TABLE IF NOT EXISTS user (id int AUTO_INCREMENT PRIMARY KEY, username VARCHAR (255), secret VARCHAR(255));
CREATE TABLE IF NOT EXISTS code (id int AUTO_INCREMENT,content VARCHAR(255),expiry TIMESTAMP, scope VARCHAR(255),PRIMARY KEY (id), user_id int, FOREIGN KEY (user_id) REFERENCES user(id));
CREATE TABLE IF NOT EXISTS token ( id int AUTO_INCREMENT, content VARCHAR(255), expiry TIMESTAMP, scope VARCHAR(255), PRIMARY KEY (id), user_id int, FOREIGN KEY (user_id) REFERENCES user(id));

INSERT INTO user (username, secret) VALUES ('alice', 'secure')