import sys
import socket
import requests
import urlparse
import re
import difflib
import random
import json
import string
import argparse


class WPPluginDetect:
    def __init__(self, url):
        self.found_plugins = []
        self.result = None
        self.port = 80
        self.full_analysis = 0
        self.randomize = 0
        self.basepath = "/"
        self.cookies = ""
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                                      " Chrome/64.0.3282.186 Safari/537.36"}
        self.page404 = []
        self.url = urlparse.urljoin(url, self.basepath)
        self.top_plugins = {'Akismet': 'akismet',
                            'Yoast SEO': 'wordpress-seo',
                            'Contact Form 7': 'contact-form-7',
                            'Jetpack by WordPress.com': 'jetpack',
                            'Wordfence Security': 'wordfence',
                            'NextGEN Gallery by Photocrati': 'nextgen-gallery',
                            'MailPoet Newsletters': 'wysija-newsletters',
                            'All in One SEO Pack': 'all-in-one-seo-pack',
                            'WP Super Cache': 'wp-super-cache',
                            'WordPress Importer': 'wordpress-importer',
                            'Google XML Sitemaps': 'google-sitemap-generator',
                            'iThemes Security': 'better-wp-security',
                            'WooCommerce': 'woocommerce',
                            'Meta Slider': 'ml-slider',
                            'Fast Secure Contact Form': 'si-contact-form',
                            'WP-Optimize': 'wp-optimize',
                            'InfiniteWP - Client': 'iwp-client',
                            'WordPress Social Sharing Optimization (WPSSO)': 'wpsso',
                            'WPtouch Mobile Plugin': 'wptouch',
                            'NextGEN Facebook (NGFB)': 'nextgen-facebook',
                            'Captcha by BestWebSoft': 'captcha',
                            'W3 Total Cache': 'w3-total-cache',
                            'Shareaholic | share buttons, analytics, related content': 'shareaholic',
                            'MailChimp': 'mailchimp',
                            'MailChimp for WordPress': 'mailchimp-for-wp',
                            'Anti-Malware Security and Brute-Force Firewall': 'gotmls',
                            'UpdraftPlus - Backup/restoration': 'updraftplus',
                            'TinyMCE Advanced': 'tinymce-advanced',
                            'Broken Link Checker': 'broken-link-checker',
                            'Contact Form by BestWebSoft': 'contact-form-plugin',
                            'Shortcodes Ultimate': 'shortcodes-ultimate',
                            'Ninja Forms': 'ninja-forms',
                            'All In One WP Security': 'all-in-one-wp-security-and-firewall',
                            'WP Statistics': 'wp-statistics',
                            'Page Builder by SiteOrigin': 'siteorigin-panels',
                            'Google Analytics by MonsterInsights': 'google-analytics-for-wordpress',
                            'WP Google Maps': 'wp-google-maps',
                            'Really Simple CAPTCHA': 'really-simple-captcha',
                            'YouTube': 'youtube-embed-plus',
                            'WP-PageNavi': 'wp-pagenavi',
                            'Breadcrumb NavXT': 'breadcrumb-navxt',
                            'Advanced Custom Fields': 'advanced-custom-fields',
                            'All-in-One Event Calendar by Time.ly': 'all-in-one-event-calendar',
                            'Google Analytics Dashboard for WP': 'google-analytics-dashboard-for-wp',
                            'Regenerate Thumbnails': 'regenerate-thumbnails',
                            'User Role Editor': 'user-role-editor',
                            'Newsletter': 'newsletter',
                            'BuddyPress': 'buddypress',
                            'Sucuri Security - Auditing, Malware Scanner and Hardening': 'sucuri-scanner',
                            'The Events Calendar': 'the-events-calendar',
                            'Black Studio TinyMCE Widget': 'black-studio-tinymce-widget',
                            'Redirection': 'redirection',
                            'WP-DB-Backup': 'wp-db-backup',
                            'WP Mail SMTP': 'wp-mail-smtp',
                            'Image Widget': 'image-widget',
                            'BackWPup - Wordpress Backup Plugin': 'backwpup',
                            'WP Smush - Image Optimization': 'wp-smushit',
                            'TablePress': 'tablepress',
                            'Google Analyticator': 'google-analyticator',
                            'Contact Form DB': 'contact-form-7-to-database-extension',
                            'WP Maintenance Mode': 'wp-maintenance-mode',
                            'Formidable Forms': 'formidable',
                            'Post Types Order': 'post-types-order',
                            'Duplicate Post': 'duplicate-post',
                            'Hello Dolly': 'hello.php',
                            'Disable Comments': 'disable-comments',
                            'WP Multibyte Patch': 'wp-multibyte-patch',
                            'Clef Two-Factor Authentication': 'wpclef',
                            'Duplicator': 'duplicator',
                            'bbpress': 'bbpress'}
        return

    def progress_bar(self, i):
        if i == 0:
            return "[          ] 0%"
        elif i == 14:
            return "[==        ] 20%"
        elif i == 28:
            return "[====      ] 40%"
        elif i == 35:
            return "[=====     ] 50%"
        elif i == 49:
            return "[=======   ] 70%"
        elif i == 63:
            return "[========= ] 90%"
        return ""

    # Check custom 404 pages
    def check_404(self, url, depth=0):
        print("Checking custom 404 pages")
        invalid_url = url
        if depth == 0:
            invalid_url += ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16)) + "/"

        try:
            url_404 = requests.get(invalid_url, cookies=self.cookies, headers=self.headers)
        except:
            return
        if url_404.status_code == 200:
            list_404 = []
            list_404.append(url_404.text)
            self.page404 += list_404
            return

    def test_wordpress(self):
        print("Verifying URL availability")

        try:
            response = requests.get(self.url, cookies=self.cookies, headers=self.headers)
            url_available = response.text
        except Exception as e:
            print("Impossible to reach %s, please check the URL" % self.url)
            exit(1)

        print("URL fine")
        self.check_404(self.url)

        # Is Wordpress present?
        print("Checking root directory structure")
        dir_list = ["wp-admin", "wp-content", "wp-includes"]
        count = 0
        for d in dir_list:
            url = self.url + d + "/"

            try:
                res = requests.get(url, cookies=self.cookies, headers=self.headers)
                if res.status != 200:
                    count -= 1
                    print("Couldn't find %s" % d)
            except Exception as e:
                print("Couldn't find %s" % d)

        print("Check for admin-ajax.php")
        url = self.url + "wp-admin/admin-ajax.php"
        admin_ajax = False

        try:
            res = requests.get(url, cookies=self.cookies, headers=self.headers)
            admin_ajax = True
            if res.status != 200:
                admin_ajax = False
                print("Couldn't find admin-ajax.php")
        except:
            print("Couldn't find admin-ajax.php")

        if count / float(len(dir_list)) > .6 or admin_ajax:  # Allows for wp-includes or wp-content to be secured
            print("WordPress Found!")
            return True
        else:
            print("Last check")
            print("Checking if wp-admin, wp-content or wp-includes are in a different location")
            dirs = re.findall("(src=|http://|https://)([^\n]*?)(wp-admin|wp-content|wp-includes)", url_available)
            hostname = urlparse.urlparse(self.url).netloc
            dirs = [(host, d) for _, host, d in dirs if hostname in host or re.match("['|\"](.|/)wp-content", host)]
            if len(dirs) > 0:
                print("WordPress Found!")
                return True
            else:
                print("WordPress was not found. It is possible that wp-includes, wp-content, and wp-admin have been"
                      " secured.")
                sys.exit(1)

    def find_plugins(self):
        print("Searching plugins")
        # TODO: Read wp-admin/admin-ajax.php
        try:
            response = requests.get(self.url, cookies=self.cookies, headers=self.headers)
            html = response.text
        except:
            print("Server error")
            sys.exit(1)

        curr_plugins = re.findall('(src=|http://|https://|href=)([^\n]*?)plugins/(.+?)/', html)
        url_struct = urlparse.urlparse(self.url)
        hostname = url_struct.netloc
        l = []
        l.append(url_struct.scheme + hostname)
        curr_plugins = [plugins for _, host, plugins in curr_plugins if difflib.get_close_matches(host, l)
                        or re.match("['|\"](.|/)wp-content", host) or hostname in host]
        curr_plugins = list(set(curr_plugins))

        self.found_plugins = self.found_plugins + curr_plugins

        for name, plugin in self.top_plugins.iteritems():
            if plugin in curr_plugins:
                self.found_plugins.append(name)
                self.found_plugins.remove(plugin)

        print("Searching plugins directory")
        # Path where all plugins lies
        path = ""
        path_groups = ""
        if len(self.found_plugins) >= 1:
            if self.found_plugins[0] in self.top_plugins:
                pattern = re.compile(".*(src=|http://|https://|href=)([^\n]*?)/plugins/"
                                     + self.top_plugins[self.found_plugins[0]] + ".*", re.DOTALL)
            else:
                pattern = re.compile(".*(src=|http://|https://|href=)([^\n]*?)/plugins/"
                                     + self.found_plugins[0] + ".*", re.DOTALL)
            path_groups = re.match(pattern, html)
            if path_groups:
                path = path_groups.group(2)
                if path[0] == "'" or path[0] == "\"":
                    path = path[1:]

        if not path:
            path = urlparse.urljoin(self.url, "wp-content")

        url_parse = urlparse.urlparse(path)
        if not url_parse.scheme == "http":
            scheme = path_groups.group(1) if path_groups else url_struct.scheme
            if not hostname in path:
                p = url_parse.path
                host_to = url_parse.netloc if url_parse.netloc else url_struct.netloc
                path = scheme + "://" + host_to + p
            else:
                path = scheme + "://" + url_parse.netloc + url_parse.path

        print("Searching for more plugins")
        i = 0
        self.check_404(path + '/plugins/')

        for item, value in self.top_plugins.items():
            progress = self.progress_bar(i)
            if progress:
                print("%s" % progress)

            url = path + '/plugins/' + value + "/"

            response = self.send_req(url)
            if not response:
                print("Invalid code or server error from %s" % url)
                continue
            html, code = response

            if not self.check_isvalid(html, code, item):
                url = url + "readme.txt"
                response = self.send_req(url)
                if not response:
                    print("Invalid code or server error from %s" % url)
                    continue
                html, code = response
                self.check_isvalid(html, code, item)
            i += 1

        if self.full_analysis:
            self.check_versions(path)

    def send_req(self, url):
        try:
            response = requests.get(url, cookies=self.cookies, headers=self.headers)
            code = response.status_code
            html = response.text
        except:
            return None
        return html, code

    def check_isvalid(self, html, code, item):
        aux_list = []
        aux_list.append(html)
        if code in [403, 200] and not difflib.get_close_matches(aux_list[0], self.page404):
            print("%s Found" % item)
            self.found_plugins.append(item)
            return True
        elif code not in [404,408,400,500,503,-1] and not difflib.get_close_matches(aux_list[0], self.page404):
            print("%s Found" % item)
            self.found_plugins.append(item)
            return True
        return False

    def check_versions(self, url):
        version_list = []
        print("Checking versions")
        for plugin in self.found_plugins:
            latest = self.get_latest(plugin)
            if plugin in self.top_plugins:
                path2 = url + '/plugins/' + self.top_plugins[plugin] + '/readme.txt'
            else:
                path2 = url + '/plugins/' + plugin + '/readme.txt'
            resp = self.send_req(path2)
            if not resp:
                version_list.append((plugin, "Unable to determine", latest))
                continue
            html, code = resp
            if not "Stable tag" in html:
                version_list.append((plugin, "Unable to determine", latest))
                continue
            pattern = re.compile(".*Stable tag:(.+?)(\r|\n)", re.DOTALL)
            groups = re.match(pattern, html)
            if not groups:
                version_list.append((plugin, "Unable to determine", latest))
                continue
            version = groups.group(1).replace(" ", "")
            version_list.append((plugin, version, latest))
        self.found_plugins = version_list
        return

    def get_latest(self, plugin):
        if plugin in self.top_plugins:
            plugin = self.top_plugins[plugin]
        resp = requests.get("http://api.wordpress.org/plugins/info/1.0/" + plugin + ".json")
        if not resp:
            return "Unable to determine"
        if resp.text == "null":
            return "Unable to determine"
        try:
            info = json.loads(resp.text)
        except:
            return "Unable to determine"
        if 'error' in info.keys() and 'plugin not found' in info['error'].lower():
            return 'Plugin does not exists anymore'
        else:
            return info["version"]

    def prettyprint(self):
        self.found_plugins.insert(0, ("     Plugin", "     Current version", "     Latest version"))
        remap = zip(*self.found_plugins)
        max_len = max(map(len,remap[0]))
        max_len2 = max(map(len,remap[1]))
        max_len3 = max(map(len,remap[2]))
        string = ""
        for (plugin, curr_version, latest_version) in self.found_plugins:
            string += ("%*s | %*s | %*s\n" % (-max_len, plugin, -max_len2, curr_version, -max_len3, latest_version))
        print("\n%s" % string)

def get_args():
    argparser = argparse.ArgumentParser(description='WP Plugin Detect')
    argparser.add_argument('--url', required=True, metavar='url', type=str, nargs='+',
                           action='store', help='URL to Crawl')
    argparser.add_argument('--port', metavar='port', type=str, nargs='+',
                           action='store', help='URL to Crawl')
    argparser.add_argument('--basepath', metavar='basepath', type=str, nargs='+',
                           action='store', help='URL to Crawl')
    argparser.add_argument('--fullanalysis', metavar='fullanalysis', type=int, nargs='+',
                           action='store', help='URL to Crawl')
    argparser.add_argument('--cookies', metavar='cookies', type=str,
                           action='store', help='Cookies')

    args = argparser.parse_args()

    return args

def main():
    args = get_args()

    WPPD = WPPluginDetect(args.url[0])

    if args.basepath:
        WPPD.basepath = args.basepath

    if args.port:
        WPPD.port = args.port

    if args.fullanalysis:
        WPPD.full_analysis = args.fullanalysis

    if args.cookies:
        cookie = SimpleCookie()
        cookie.load(args.cookies)
        args.cookies = {key: value.value for key, value in cookie.items()}
    WPPD.cookies = args.cookies

    WPPD.test_wordpress()
    WPPD.find_plugins()
    WPPD.found_plugins = list(set(WPPD.found_plugins))
    print("The following %d plugins were found:\n" % len(WPPD.found_plugins))
    if WPPD.full_analysis:
        WPPD.prettyprint()
    else:
        print(WPPD.found_plugins)
    return True

if __name__ == '__main__':
    print "Running WordPress Plugin Detect"
    main()
