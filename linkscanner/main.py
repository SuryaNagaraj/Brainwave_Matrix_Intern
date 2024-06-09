import tldextract
import Levenshtein as lv

legitimate_domains = ['example.com', 'google.com']

test_urls = [
    'http://example.co',
    'https://www.google.co.in/'
]


def extract_domain_parts(url):
    extracted = tldextract.extract(url)
    return extracted.subdomain, extracted.domain, extracted.suffix


def is_misspelled_domain(domain, legitimate_domains, threshold=0.9):
    for legit_domain in legitimate_domains:
        similarity = lv.ratio(domain, legit_domain)
        if similarity >= threshold:
            return False
    return True


def is_phishing_url(url, legitimate_domains):
    subdomain, domain, suffix = extract_domain_parts(url)

    # check if it's a known legitimate_domains
    if f"{domain}.{suffix}" in legitimate_domains:
        return False

    # check for misspelled domain names
    if is_misspelled_domain(domain, legitimate_domains):
        print(f"Potential phishing detected: {url}")
        return True
    # you can add more checks here, like suspicious subdomains
    return False


# press the green button in the gutter to run the script.
if __name__ == '__main__':
    for url in test_urls:
        is_phishing_url(url, legitimate_domains)  # type: ignore




