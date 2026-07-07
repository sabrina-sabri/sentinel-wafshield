USE labdb;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password CHAR(64) NOT NULL
);

INSERT INTO users (username, password)
VALUES
('admin', SHA2('admin123', 256)),
('alice', SHA2('password123', 256)),
('bob', SHA2('welcome123', 256));

CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO comments (username, comment) VALUES
('admin', 'Welcome to the demo app!'),
('alice', 'This is a test comment.');
