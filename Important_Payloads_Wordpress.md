|**Command**|**Description**|
|---|---|
|`tree -L 1`|Lists contents of current directory|
|`curl -s -X GET <url>`|Makes a GET request to a webserver and receives HTML source code of requested web page|
|`curl -I -X GET <url>`|Prints the response header of the GET request from the requested web page|
|`curl -X POST -d <data> <url>`|Sends a POST request with data to specific webserver|
|`wpscan --url <url> -e ap`|Scans specific WordPress application to enumerate plugins|
|`wpscan --url <url> -e u`|Scans specific WordPress application to enumerate users|
|`msfconsole`|Starts Metasploit Framework|
|`html2text`|Converts redirected HTML output or files to easily readable output|
|`grep <pattern>`|Filters specific pattern in files or redirected output|
|`jq`|Transforms JSON input and streams of JSON entities|
|`man <tool>`|Man provides you with the manpage of the specific tool|
#### File Structure
```shell-session
alakin2504@htb[/htb]$ tree -L 1 /var/www/html
.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php└── xmlrpc.php
```

## Key WordPress Files
The root directory of WordPress contains files that are needed to configure WordPress to function correctly.

- `index.php` is the homepage of WordPress.
    
- `license.txt` contains useful information such as the version WordPress installed.
    
- `wp-activate.php` is used for the email activation process when setting up a new WordPress site.
    
- `wp-admin` folder contains the login page for administrator access and the backend dashboard. 
    - `/wp-admin/login.php`
    - `/wp-admin/wp-login.php`
    - `/login.php`
    - `/wp-login.php`

This file can also be renamed to make it more challenging to find the login page.

- `xmlrpc.php` is a file representing a feature of WordPress that enables data to be transmitted with HTTP

---

## WordPress Configuration File

#### wp-config.php
```php
<?php
/** <SNIP> */
/** The name of the database for WordPress */
define( 'DB_NAME', 'database_name_here' );

/** MySQL database username */
define( 'DB_USER', 'username_here' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password_here' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Authentication Unique Keys and Salts */
/* <SNIP> */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/** WordPress Database Table prefix */
$table_prefix = 'wp_';

/** For developers: WordPress debugging mode. */
/** <SNIP> */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

## Key WordPress Directories
#### WP-Content
```shell-session
alakin2504@htb[/htb]$ tree -L 1 /var/www/html/wp-content
.
├── index.php
├── plugins
└── themes
```

#### WP-Includes
```shell-session
alakin2504@htb[/htb]$ tree -L 1 /var/www/html/wp-includes
.
├── <SNIP>
├── theme.php
├── update.php
├── user.php
├── vars.php
├── version.php
├── widgets
├── widgets.php
├── wlwmanifest.xml
├── wp-db.php
└── wp-diff.php
```
