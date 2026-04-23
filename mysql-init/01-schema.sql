CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE,
  email VARCHAR(200) UNIQUE,
  password VARCHAR(200),
  role VARCHAR(20) DEFAULT 'user',
  twofa_secret VARCHAR(10) DEFAULT '000000',
  reset_token VARCHAR(100),
  bio TEXT
);

CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(150),
  description TEXT,
  price DECIMAL(10,2),
  category VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  product_id INT,
  total DECIMAL(10,2),
  note TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_flags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  attack_key VARCHAR(100) UNIQUE,
  flag_value VARCHAR(120)
);

INSERT INTO users (username,email,password,role,twofa_secret,bio) VALUES
('admin','admin@shop.local','admin123','admin','111111','I am admin'),
('alice','alice@shop.local','alice123','user','222222','hello'),
('bob','bob@shop.local','bob123','user','333333','safe user')
ON DUPLICATE KEY UPDATE username=username;

INSERT INTO products (name,description,price,category) VALUES
('Gaming Mouse','RGB mouse',49.90,'electronics'),
('Mechanical Keyboard','Blue switches',89.00,'electronics'),
('Coffee Mug','Large mug',12.50,'home'),
('Notebook','Paper notebook',5.30,'office');

INSERT INTO orders (user_id,product_id,total,note) VALUES
(2,1,49.90,'first order'),
(2,3,12.50,'gift'),
(3,2,89.00,'office setup');

INSERT INTO attack_flags (attack_key,flag_value) VALUES
('sqli_inband','DIGITAL[9f2a1c43]'),
('sqli_blind_boolean','DIGITAL[11d7e5aa]'),
('sqli_time','DIGITAL[c4bb8a12]'),
('sqli_second_order','DIGITAL[3a8fe91c]'),
('sqli_oob','DIGITAL[e7f90b54]'),
('nosqli','DIGITAL[55ab2fd0]'),
('command_injection','DIGITAL[91a6de33]'),
('code_injection','DIGITAL[7ed4bc90]'),
('host_header_injection','DIGITAL[dc6602a1]'),
('xxe','DIGITAL[a2f8ce71]'),
('ssti','DIGITAL[8be1d045]'),
('auth_enumeration','DIGITAL[4c30fb92]'),
('auth_bruteforce','DIGITAL[6d271ea8]'),
('auth_forgot_bruteforce','DIGITAL[2e9f4ab1]'),
('auth_2fa_bruteforce','DIGITAL[b9d8cc40]'),
('default_credentials','DIGITAL[f3aa0159]'),
('http_verb_tamper','DIGITAL[cb82d7f6]'),
('idor','DIGITAL[3d19a60f]'),
('bypass_2fa_direct','DIGITAL[d7a3fb22]'),
('bypass_auth_direct','DIGITAL[67be20c8]'),
('privesc','DIGITAL[154e8bd2]'),
('upload_bypass','DIGITAL[8a4b1ff7]'),
('lfi','DIGITAL[c6f59103]'),
('rfi','DIGITAL[2bb7de6e]'),
('path_traversal','DIGITAL[e0a1c4d8]')
ON DUPLICATE KEY UPDATE flag_value=VALUES(flag_value);
