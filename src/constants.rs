// Nginx configuration constants
pub const SITES_PATH: &'static str = "/var/www/html";
pub const SITES_SSL_PATH: &'static str = "/etc/nginx/ssl";
pub const NGINX_CONF_D_PATH: &'static str = "/etc/nginx/conf.d";
pub const NGINX_HTTP_TEMPLATE: &'static str = include_str!("./assets/http.conf.template");
pub const NGINX_HTTPS_TEMPLATE: &'static str = include_str!("./assets/https.conf.template");
pub const NGINX_HTTP_CONFIG_MARKER: &'static str = "######E2SP-HTTP-CONFIGURATION######";
pub const NGINX_HTTPS_CONFIG_MARKER: &'static str = "######E2SP-HTTPS-CONFIGURATION######";

// WordPress download URL constant
pub const LATEST_WORDPRESS_URL: &'static str = "https://wordpress.org/latest.tar.gz";

// Database configuration constants
pub const DB_ROOT_USER: &'static str = "root";
pub const DB_USER: &'static str = "wordpress";
pub const DB_PASSWORD: &'static str = "pleaseadvise";
pub const DB_HOST: &'static str = "localhost";
pub const DB_PORT: u16 = 3306;
pub const DB_CHARSET: &'static str = "utf8mb4";
pub const DB_COLLATION: &'static str = "utf8mb4_general_ci";