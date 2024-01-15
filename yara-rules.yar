rule OpenAPI_Detection {
    meta:
        description = "Detects OpenAPI based on HTTP method, path, and response"
        author = "Equators"
        reference = "https://www.openapis.org/"
        severity = "Info"
        cvss_score = "0"
        mitre_att = ""
    strings:
        $path = "/openapi.json"
        $keywords = "openapi paths"
        $content_type = "application/openapi+json"
    condition:
    
        http.method == "GET" and
        $path in (http.request.uri) and
        all of ($keyword in http.request.uri, for $keyword in $keywords) and
        (http.response.body contains $keywords or http.response.headers["Content-Type"] contains $content_type) and
        http.response.status == 200
}

rule Couchbase_Buckets_Unauthenticated_REST_API {
    meta:
        description = "Detects Couchbase Buckets REST API without authentication based on HTTP method, path, and response"
        author = "Equators"
        reference = "https://docs.couchbase.com/server/current/rest-api/rest-bucket-intro.html, https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-couchbase-bucket.html"
        severity = "Medium"
        cvss_score = "5.3"
        mitre_att = "CWE-200"
    strings:
        $path = "/pools/default/buckets"
        $keywords = "couchbase bucket data"
        $content_type = "application/json"
    condition:
        http.method == "GET" and
        $path in (http.request.uri) and
        http.response.status == 200 and
        all of ($keyword in http.response.body, for $keyword in $keywords) and
        http.response.headers["Content-Type"] contains $content_type
}


rule Drupal_JSONAPI_Username_Listing_Detection {
    meta:
        description = "Detects Drupal JSON:API username listing based on HTTP method, path, and response"
        author = "Equators"
        reference = "https://www.drupal.org/project/drupal/issues/3240913"
        severity = "medium"
        cvss_score = "5.3"
        mitre_att = ""
    strings:
        $regex_pattern = /\{"display_name":"([A-Za-z0-9-_]+)"\}/
    condition:
        http.method == "GET" and
        $regex_pattern at 0 and
        http.response.status == 200
}


rule Settings_PHP_Files_Information_Disclosure {
    meta:
        description = "Detects settings.php source code disclosure via backup files"
        author = "Equators"
        severity = "medium"
        cvss_score = "5.3"
        mitre_att = ""
    strings:
        $backup_files = /settings\.php\.(bak|dist|old|save|swp|txt)/
    condition:
        http.method == "GET" and
        $backup_files at 0 and
        ("DB_NAME" or "DB") in http.response.body and
        http.response.status == 200
}

rule Websheets_Configuration_File_Detect {
    meta:
        description = "Detects Websheets configuration file exposure"
        author = "Equators"
        severity = "high"
        cvss_score = "7.5"
        mitre_att = ""
    strings:
        $config_file_1 = /ws-config\.json/
        $config_file_2 = /ws-config\.example\.json/
    condition:
        http.method == "GET" and
        (
            ($config_file_1 at 0 and $config_file_2 in (http.request.uri)) or
            ($config_file_2 at 0 and $config_file_1 in (http.request.uri))
        ) and
        (
            (contains(http.response.body, "\"db-password\":") and contains(http.response.body, "\"db-database\":") and http.response.status == 200)
        )
}


rule Django_Secret_Key_Exposure {
    meta:
        description = "Detects Django settings.py file containing a secret key"
        author = "Equators"
        severity = "high"
        mitre_att = ""
    strings:
        $file_1 = /manage\.py/
        $file_2 = /settings\.py/
        $file_3 = /app\/settings\.py/
        $file_4 = /django\/settings\.py/
        $file_5 = /settings\/settings\.py/
        $file_6 = /web\/settings\/settings\.py/
        $file_7 = /{{app_name}}\/settings\.py/
        $secret_key = /SECRET_KEY =/
        $html_content = /text\/html/
        $django_secret_key = /"DJANGO_SECRET_KEY", "(.*)"/
        $app_name = /os\.environ\.setdefault\(["']DJANGO_SETTINGS_MODULE["'],\s["']([a-zA-Z-_0-9]*).settings["']\)/
    condition:
        http.method == "GET" and
        (
            ($file_1 in (http.request.uri) and $file_2 at 0) or
            ($file_2 in (http.request.uri) and $file_2 at 0) or
            ($file_3 in (http.request.uri) and $file_3 at 0) or
            ($file_4 in (http.request.uri) and $file_4 at 0) or
            ($file_5 in (http.request.uri) and $file_5 at 0) or
            ($file_6 in (http.request.uri) and $file_6 at 0) or
            ($file_7 in (http.request.uri) and $file_7 at 0)
        ) and
        $secret_key in (http.response.body) and
        not ($html_content in (http.response.headers) or $html_content in (http.response.body)) and
        http.response.status == 200 and
        (
            ($django_secret_key at 0 and $django_secret_key in (http.response.body)) or
            ($app_name at 0 and $app_name in (http.response.body))
        )
}

rule Kubernetes_Etcd_Keys_Exposure {
    meta:
        description = "Detects exposure of Kubernetes etcd keys"
        author = "Hardik-Solanki"
        severity = "medium"
        mitre_att = ""
    strings:
        $file_path = /apiserver-etcd-client\.key/
        $private_key_indicator = /(?m)^-----BEGIN PRIVATE KEY-----/
        $json_content_type = /application\/json/
        $html_content_type = /application\/html/
    condition:
        http.method == "GET" and
        $file_path in (http.request.uri) and
        $private_key_indicator in (http.response.body) and
        not (($json_content_type in (http.response.headers) or $json_content_type in (http.response.body)) or
             ($html_content_type in (http.response.headers) or $html_content_type in (http.response.body))) and
        http.response.status == 200
}

rule Firebase_Debug_Log_File_Exposure {
    meta:
        description = "Detects exposure of Firebase Debug Log file"
        author = "Hardik-Solanki"
        severity = "low"
        mitre_att = ""
    strings:
        $file_path = /firebase-debug\.log/
        $debug_keywords = /[debug]|[firebase]|[googleapis\.com]/
    condition:
        http.method == "GET" and
        $file_path in (http.request.uri) and
        all of ($debug_keywords in (http.response.body)) and
        http.response.status == 200
}

rule Git_Metadata_Directory_Exposure {
    meta:
        description = "Detects exposure of Git Metadata Directory"
        author = "tess"
        severity = "medium"
        mitre_att = ""
    strings:
        $directory_path = /\.git\//
        $forbidden_message = /403 Forbidden|You do not have permission to access \/.git\//
    condition:
        http.method == "GET" and
        $directory_path in (http.request.uri) and
        all of ($forbidden_message in (http.response.body)) and
        http.response.status == 403
}

rule Heroku_API_Key_Exposure {
    meta:
        description = "Detects exposure of Heroku API Key"
        author = "DhiyaneshDK"
        severity = "info"
        mitre_att = ""
    strings:
        $heroku_key_pattern = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/
    condition:
        http.method == "GET" and
        $heroku_key_pattern in (http.response.body) and
        http.response.status == 200
}

// Fuzzing
//1
rule Cache_Poison_Fuzzing {
    meta:
        description = "Detects Cache Poisoning Fuzzing attempt"
        author = "dwisiswant0,ColbyJack1134"
        severity = "info"
        mitre_att = ""
        reference = "https://youst.in/posts/cache-poisoning-at-scale/ https://portswigger.net/web-security/web-cache-poisoning"
    strings:
        $user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"
        $host_header = "Host: {{Hostname}}"
        $contains_randstr_1 = "{{randstr}}"
        $contains_randstr_2 = "{{randstr}}"
    condition:
        all of them and
        http.method == "GET" and
        $user_agent in (http.request.headers) and
        $host_header in (http.request.headers) and
        all of ($contains_randstr_1 in (http.response.body_1), $contains_randstr_2 in (http.response.body_2)) and
        http.response.status == 200
}

rule Header_Command_Injection {
    meta:
        description = "Detects Header Remote Command Injection"
        author = "geeknik"
        severity = "critical"
        cvss-metrics = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        cvss-score = 10
        cwe-id = "CWE-77"
        mitre_att = ""
    strings:
        $http_method = "GET /?{{header}} HTTP/1.1"
        $host_header = "Host: {{Hostname}}"
        $payload_header = "{{header}}: {{payload}}"
        $uid_string = "uid="
        $gid_string = "gid="
        $groups_string = "groups="
        $root_regex = "root:.*:0:0:"
    condition:
        $http_method in (http.request.data) and
        $host_header in (http.request.data) and
        $payload_header in (http.request.data) and
        (
            all of ($uid_string in (http.response.body), $gid_string in (http.response.body), $groups_string in (http.response.body)) or
            $root_regex in (http.response.body)
        )
}

rule IIS_ShortName_Detect {
    meta:
        description = "Detects IIS Short Name Vulnerability"
        author = "nodauf"
        severity = "info"
        cvss-metrics = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        cvss-score = 0
        cwe-id = "CWE-200"
        mitre_att = ""
    strings:
        $http_request_1 = "GET /N0t4xist*~1*/a.aspx HTTP/1.1"
        $http_request_2 = "GET /*~1*/a.aspx' HTTP/1.1"
        $http_request_3 = "OPTIONS /N0t4xist*~1*/a.aspx HTTP/1.1"
        $http_request_4 = "OPTIONS /*~1*/a.aspx' HTTP/1.1"
        $status_code_1 = "status_code_1!=404 && status_code_2 == 404 || status_code_3 != 404 && status_code_4 == 404"
    condition:
        any of (
            all of ($http_request_1 in (http.request.data), $status_code_1 in (http.response.body)),
            all of ($http_request_2 in (http.request.data), $status_code_1 in (http.response.body)),
            all of ($http_request_3 in (http.request.data), $status_code_1 in (http.response.body)),
            all of ($http_request_4 in (http.request.data), $status_code_1 in (http.response.body))
        )
}


rule MDB_Database_File {
    meta:
        description = "Detects Microsoft Access Database File"
        author = "pdteam"
        severity = "medium"
        cvss-metrics = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        cvss-score = 5.3
        cwe-id = "CWE-200"
        reference = "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.5-Testing_for_MS_Access.html"
    strings:
        $http_request = "GET {{mdbPaths}} HTTP/1.1\r\nHost: {{Hostname}}\r\nOrigin: {{BaseURL}}\r\nAccept-Language: en-US,en;q=0.9"
        $mdb_paths = "helpers/wordlists/mdb-paths.txt"
        $binary_pattern = { 000100005374616E64617264204A657420444200 } // mdb
        $content_type_header = "application/x-msaccess"
        $status_code_200 = "200"
    condition:
        all of them
}


rule PrestaShop_Module_Enumeration {
    meta:
        description = "Prestashop Modules Enumeration"
        author = "meme-lord"
        severity = "info"
    strings:
        $http_request = "GET /modules/{{path}}/config.xml HTTP/1.1\r\nHost: {{Hostname}}\r\nAccept: application/json, text/plain, */*\r\nAccept-Language: en-US,en;q=0.5\r\nReferer: {{BaseURL}}"
        $prestashop_modules = "helpers/wordlists/prestashop-modules.txt"
        $module_tags = { "<module>", "<name>", "<displayName>", "<is_configurable>", "</module>" }
        $status_code_200 = "200"
        $version_regex = "<version>(<!\\[CDATA\\[)?([0-9.]+)"
    condition:
        all of them
}

rule SSRF_via_Proxy_Unsafe {
    meta:
        description = "SSRF via Proxy Unsafe"
        author = "geeknik, petergrifin"
        severity = "unknown"
    strings:
        $http_request = "{ {verb}} http://127.0.0.1:22 HTTP/1.1\r\nHost: {{Hostname}}"
        $verbs = "GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH"
        $protocol_mismatch = "Protocol mismatch"
        $openssh = "OpenSSH"
        $status_code_200 = "200"
    condition:
        all of them
}


rule WordPress_Plugins_Detection {
    meta:
        description = "WordPress Plugins Detection"
        author = "0xcrypto"
        severity = "info"
    strings:
        $http_request = "GET /wp-content/plugins/{{pluginSlug}}/readme.txt HTTP/1.1\r\nHost: {{Hostname}}"
        $status_code_200 = "200"
        $description_marker = "== Description =="
        $plugin_name_regex = "===\s(.*)\s==="
        $plugin_version_regex = "(?m)Stable tag: ([0-9.]+)"
    condition:
        all of them
}


rule WordPress_Theme_Detection {
    meta:
        description = "WordPress Theme Detection"
        author = "0xcrypto"
        severity = "info"
    strings:
        $http_request = "GET /wp-content/themes/{{themeSlug}}/readme.txt HTTP/1.1\r\nHost: {{Hostname}}"
        $status_code_200 = "200"
        $description_marker = "== Description =="
    condition:
        all of them
}


rule WordPress_Weak_Credentials {
    meta:
        description = "WordPress Weak Credentials"
        author = "evolutionsec"
        severity = "critical"
        reference = "https://www.wpwhitesecurity.com/strong-wordpress-passwords-wpscan/"
        cvss_metrics = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
        cvss_score = 9.3
        cwe_id = "CWE-1391"
    strings:
        $http_request = "POST /wp-login.php HTTP/1.1\r\nHost: {{Hostname}}\r\nOrigin: {{BaseURL}}\r\nContent-Type: application/x-www-form-urlencoded\r\nReferer: {{BaseURL}}\r\n\r\nlog={{users}}&pwd={{passwords}}"
        $header_check_1 = "/wp-admin"
        $header_check_2 = "wordpress_logged_in"
        $status_302 = "302"
    condition:
        all of them
}


//honeypot

rule Citrix_Honeypot_Detect {
    meta:
        description = "Citrix Honeypot Detection"
        author = "equators"
        severity = "info"
        reference = ""
        mitre_attk = "TBD"  // Fill in the appropriate MITRE ATT&CK ID
        verified = true
        max_request = 1
        vendor = "citrix"
        product = "citrix"
        shodan_query = "http.title:\"Citrix Login\""
    strings:
        $http_get_request = "GET {{BaseURL}}"
        $body_length_check = "len(body)<2000"
        $title_check = "<title>Citrix Login</title>"
        $terms_of_service_check = "In order to use our services, you must agree to Citrix's Terms of Service."
    condition:
        all of them
}

rule Dionaea_HTTP_Honeypot_Detect {
    meta:
        description = "Dionaea HTTP Honeypot Detection"
        author = "equators"
        mitre_attk = ""
        severity = "info"
        verified = true
        max_request = 1
        vendor = "dionaea"
        product = "http"
    strings:
        $http_request = "AAAA / HTTP/1.1\nHost: {{Hostname}}"
        $status_501_check = "501 Not Implemented"
        $nginx_check = "nginx"
        $xml_declaration_check = '<?xml version="1.0" encoding="ascii"?>'
    condition:
        all of them
}


rule ElasticPot_Honeypot_Detect {
    meta:
        description = "ElasticPot Honeypot Detection"
        author = "equators"
        mitre_attk = ""
        severity = "info"
        max_request = 1
        vendor = "elasticpot"
        product = "elasticsearch"
        fofa_query = "index_not_found_exception"
    strings:
        $clusterSettings = "/_cluster/settings"
        $indexNotFoundException = "index_not_found_exception"
    condition:
        any of them
}


rule Snare_Honeypot_Detect {
    meta:
        description = "Snare Honeypot Detection"
        author = "equators"
        mitre_attk = ""
        severity = "info"
        verified = true
        max_request = 1
        vendor = "snare"
        product = "http"
        shodan_query = "\"Python/3.10 aiohttp/3.8.3\" && Bad status"
    strings:
        $getRequest = "GET / HTTP/1337"
        $expectedHeader = "Python/3.10 aiohttp/3.8.3"
        $badStatus = "Bad status line 'Expected dot'"
    condition:
        all of them
}

