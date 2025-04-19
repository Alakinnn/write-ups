] User(s) Identified:

[+] web-admin
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.trilocor.local/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Oembed API - Author URL (Aggressive Detection)
 |   - http://www.trilocor.local/wp-json/oembed/1.0/embed?url=http://www.trilocor.local/&format=json
 |  Author Sitemap (Aggressive Detection)
 |   - http://www.trilocor.local/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] pr-martins
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] web-editor
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] hr-smith
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] r.batty
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] trilocor.Emerald
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] trilocor.Shiv
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] trilocor.Gradin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] trilocor.Vagient
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] trilocor.Fankle
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://www.trilocor.local/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://www.trilocor.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://www.trilocor.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0.2 identified (Insecure, released on 2022-08-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://www.trilocor.local/index.php/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>
 |  - http://www.trilocor.local/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.0.2</generator>

[+] WordPress theme in use: astra
 | Location: http://www.trilocor.local/wp-content/themes/astra/
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://www.trilocor.local/wp-content/themes/astra/readme.txt
 | [!] The version is out of date, the latest version is 4.10.0
 | Style URL: http://www.trilocor.local/wp-content/themes/astra/style.css
 | Style Name: Astra
 | Style URI: https://wpastra.com/
 | Description: Astra is fast, fully customizable & beautiful WordPress theme suitable for blog, personal portfolio,...
 | Author: Brainstorm Force
 | Author URI: https://wpastra.com/about/?utm_source=theme_preview&utm_medium=author_link&utm_campaign=astra_theme
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 3.9.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://www.trilocor.local/wp-content/themes/astra/style.css, Match: 'Version: 3.9.2'
elementor 3.7.7

[SUCCESS] - pr-martins / martins