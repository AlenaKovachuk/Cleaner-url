from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re


app = Flask(__name__)

SUSPICIOUS_DOMAINS = [
    'phishing-site.ru', 'fake-login.com', 'virus-download.net',
    'bit.ly', 'tinyurl.com', 'ow.ly', 'cutt.ly', 'clck.ru',
    'short.link', 'is.gd', 'goo.gl', 'rb.gy', 'rebrand.ly',
    'shorturl.at', 'shorte.st', 'adf.ly', 'bc.vc', 't.co'
]

TRACKERS = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_cid', 'utm_reader', 'utm_viz', 'utm_pubreferrer',
    'utm_guid', 'utm_nooverride', 'vero_conv',
    'fbclid', 'gclid', 'yclid', 'mc_cid', 'mc_eid', '_ga', '_gl',
    'hsCtaTracking', 'ref', 'source', 'click_id', 'tracking', 'icid',
    'mkt_tok', 'trk', 'trkCampaign', 'trkContent', 'trkMedium',
    'affiliate_id', 'aff_id', 'clickid', 'tracking_code'
]


def clean_url(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)

        if not parsed.netloc:
            return 'Ошибка: некорректный URL (нет домена)'

        query_params = parse_qs(parsed.query, keep_blank_values=False)

        cleaned_params = {k: v for k, v in query_params.items() if k not in TRACKERS}

        important_params = ['id', 'page', 'p', 'post_id', 'product_id', 'article']
        kept_important = {k: v for k, v in cleaned_params.items() if k in important_params}

        if kept_important:
            new_query = urlencode(kept_important, doseq=True)
        else:
            new_query = urlencode(cleaned_params, doseq=True) if cleaned_params else ''

        cleaned_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return cleaned_url

    except Exception as e:
        return f'Ошибка очистки: {e}'


def check_domain_safety(url):
    try:
        if url.startswith('Ошибка'):
            return url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if not domain:
            return 'ОШИБКА: не удалось определить домен'

        if domain.startswith('www.'):
            domain = domain[4:]

        for bad in SUSPICIOUS_DOMAINS:
            if bad in domain:
                return f'ОПАСНО: домен "{domain}" найден в чёрном списке! Не переходите по ссылке!'

        domain_parts = domain.split('.')
        if len(domain) < 10 and len(domain_parts) >= 2:
            safe_short = ['io', 'co', 'me', 'tv', 'to', 'gg', 'li']
            if len(domain_parts) >= 2 and domain_parts[-1] in safe_short:
                if len(domain_parts[0]) < 3:
                    return f'ВНИМАНИЕ: подозрительно короткий домен "{domain}" — возможна фишинговая ссылка'

        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain.split(':')[0]):
            return f'ОПАСНО: ссылка ведёт на IP-адрес "{domain}" — часто используется в фишинге'

        if '@' in url and url.index('@') > url.find('//') + 2:
            return f'ОПАСНО: URL содержит символ "@" — возможна маскировка адреса'

        return 'Домен безопасен'

    except Exception as e:
        return f'Ошибка проверки: {e}'


def count_trackers_removed(original_url, cleaned_url):
    try:
        if cleaned_url.startswith('Ошибка'):
            return 0

        if not original_url.startswith(('http://', 'https://')):
            original_url = 'http://' + original_url

        orig_params = parse_qs(urlparse(original_url).query, keep_blank_values=False)
        removed = sum(1 for k in orig_params if k in TRACKERS)

        return removed

    except Exception as e:
        return 0


def get_domain_info(url):
    try:
        if url.startswith('Ошибка'):
            return {'domain': 'Неизвестно', 'full_domain': 'Неизвестно'}

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if domain.startswith('www.'):
            domain = domain[4:]

        return {
            'domain': domain.split('.')[0] if '.' in domain else domain,
            'full_domain': domain
        }
    except:
        return {'domain': 'Неизвестно', 'full_domain': 'Неизвестно'}


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None

    if request.method == 'POST':
        original_url = request.form.get('url', '').strip()

        if original_url:
            display_original = original_url

            cleaned_url = clean_url(original_url)

            safety_status = check_domain_safety(original_url)

            trackers_removed = count_trackers_removed(original_url, cleaned_url)
            domain_info = get_domain_info(original_url)
            was_cleaned = (original_url != cleaned_url and
               not cleaned_url.startswith('Ошибка'))

            result = {
                'original': display_original,
                'cleaned': cleaned_url,
                'safety': safety_status,
                'trackers_removed': trackers_removed,
                'domain_info': domain_info,
                'was_cleaned': was_cleaned
            }

    return render_template('index.html', result=result)


@app.route('/api/clean', methods=['POST'])
def api_clean():

    import json
    data = json.loads(request.data)
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL не указан'}), 400

    cleaned = clean_url(url)
    safety = check_domain_safety(url)
    removed = count_trackers_removed(url, cleaned)

    return jsonify({
        'original': url,
        'cleaned': cleaned,
        'safety': safety,
        'trackers_removed': removed
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
