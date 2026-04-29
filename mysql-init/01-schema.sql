CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE,
  email VARCHAR(200) UNIQUE,
  password VARCHAR(200),
  role VARCHAR(20) DEFAULT 'user',
  twofa_secret VARCHAR(10) DEFAULT NULL,
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

CREATE TABLE IF NOT EXISTS wishlists (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  product_id INT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_tickets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  subject VARCHAR(200),
  message TEXT,
  status VARCHAR(20) DEFAULT 'open',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username,email,password,role,twofa_secret,bio) VALUES
('admin','admin@shop.local','5f2481ab267d55a011d5ca56af2f09e3','admin','0000','I am admin'),
('alice','alice@shop.local','19cd62ee0e1eb7d09f8626f7b6104cee','user','0000','hello'),
('bob','bob@shop.local','8d51fc8ef5e64989d1d142d0c04edd41','user','0000','safe user'),
('mira','mira@shop.local','eedf7968ab3fc97499fa87924932531a','user','0000','qa account'),
('niko','niko@shop.local','c8dd1245071361874f350c270d13faca','user','0000','sales account')
ON DUPLICATE KEY UPDATE username=username;

INSERT INTO products (name,description,price,category) VALUES
('Gaming Mouse','RGB mouse',49.90,'electronics'),
('Mechanical Keyboard','Blue switches',89.00,'electronics'),
('Coffee Mug','Large mug',12.50,'home'),
('Notebook','Paper notebook',5.30,'office');

INSERT INTO orders (user_id,product_id,total,note) VALUES
(2,1,49.90,'first order'),
(2,3,12.50,'gift'),
(3,2,89.00,'office setup'),
(4,4,5.30,'notebook refill'),
(5,1,49.90,'late night gaming');

INSERT INTO wishlists (user_id,product_id) VALUES
(2,2),
(3,1);

INSERT INTO support_tickets (user_id,subject,message,status) VALUES
(2,'Delivery question','Where is my order #2?','open'),
(3,'Invoice request','Need invoice copy for order #3','closed');
