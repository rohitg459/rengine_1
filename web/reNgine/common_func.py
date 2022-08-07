import json
import logging
import os
import random
import re
import shutil
import subprocess
from datetime import date
from functools import reduce
from threading import Thread
from urllib.parse import urlparse

import asyncwhois
import requests
import tldextract
from discord_webhook import DiscordWebhook
from django.db.models import Q
from lxml import html
from reNgine.common_serializers import *
from reNgine.definitions import *
from scanEngine.models import *
from startScan.models import *
from targetApp.models import *


def execute_live(cmd):
    """Execute a command while fetching it's output live."""
    popen = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        item = stdout_line.strip()
        if item.startswith(('{', '[')) and item.endswith(('}', ']')):
            try:
                yield json.loads(item)
                continue
            except Exception as e:
                pass
        yield item
    popen.stdout.close()
    return_code = popen.wait()
    return return_code

def get_lookup_keywords():
    default_lookup_keywords = [
        key.strip() for key in InterestingLookupModel.objects.get(
            id=1).keywords.split(',')]
    custom_lookup_keywords = []
    if InterestingLookupModel.objects.filter(custom_type=True):
        custom_lookup_keywords = [
            key.strip() for key in InterestingLookupModel.objects.filter(
                custom_type=True).order_by('-id')[0].keywords.split(',')]
    lookup_keywords = default_lookup_keywords + custom_lookup_keywords
    # remove empty strings from list, if any
    lookup_keywords = list(filter(None, lookup_keywords))

    return lookup_keywords


def get_interesting_subdomains(scan_history=None, target=None):
    lookup_keywords = get_lookup_keywords()

    subdomain_lookup_query = Q()
    page_title_lookup_query = Q()

    for key in lookup_keywords:
        if InterestingLookupModel.objects.filter(custom_type=True).exists():
            if InterestingLookupModel.objects.filter(
                    custom_type=True).order_by('-id')[0].url_lookup:
                subdomain_lookup_query |= Q(name__icontains=key)
            if InterestingLookupModel.objects.filter(
                    custom_type=True).order_by('-id')[0].title_lookup:
                page_title_lookup_query |= Q(
                    page_title__iregex="\\y{}\\y".format(key))
        else:
            subdomain_lookup_query |= Q(name__icontains=key)
            page_title_lookup_query |= Q(
                page_title__iregex="\\y{}\\y".format(key))

    if InterestingLookupModel.objects.filter(
            custom_type=True) and InterestingLookupModel.objects.filter(
            custom_type=True).order_by('-id')[0].condition_200_http_lookup:
        subdomain_lookup_query &= Q(http_status__exact=200)
        page_title_lookup_query &= Q(http_status__exact=200)

    subdomain_lookup = Subdomain.objects.none()
    title_lookup = Subdomain.objects.none()

    if target:
        subdomains = Subdomain.objects.filter(target_domain__id=target)
        if subdomain_lookup_query:
            subdomain_lookup = subdomains.filter(subdomain_lookup_query)
        if page_title_lookup_query:
            title_lookup = subdomains.filter(page_title_lookup_query)
    elif scan_history:
        subdomains = Subdomain.objects.filter(scan_history__id=scan_history)
        if subdomain_lookup_query:
            subdomain_lookup = subdomains.filter(subdomain_lookup_query)
        if page_title_lookup_query:
            title_lookup = subdomains.filter(page_title_lookup_query)
    else:
        if subdomain_lookup_query:
            subdomain_lookup = Subdomain.objects.filter(subdomain_lookup_query)
        if page_title_lookup_query:
            title_lookup = Subdomain.objects.filter(page_title_lookup_query)
    lookup = subdomain_lookup | title_lookup
    return lookup


def get_interesting_endpoint(scan_history=None, target=None):
    lookup_keywords = get_lookup_keywords()

    url_lookup_query = Q()
    page_title_lookup_query = Q()

    for key in lookup_keywords:
        if InterestingLookupModel.objects.filter(custom_type=True).exists():
            if InterestingLookupModel.objects.filter(custom_type=True).order_by('-id')[0].url_lookup:
                url_lookup_query |= Q(http_url__icontains=key)
            if InterestingLookupModel.objects.filter(custom_type=True).order_by('-id')[0].title_lookup:
                page_title_lookup_query |= Q(page_title__iregex="\\y{}\\y".format(key))

        else:
            url_lookup_query |= Q(http_url__icontains=key)
            page_title_lookup_query |= Q(page_title__iregex="\\y{}\\y".format(key))

    if InterestingLookupModel.objects.filter(custom_type=True) and InterestingLookupModel.objects.filter(custom_type=True).order_by('-id')[0].condition_200_http_lookup:
        url_lookup_query &= Q(http_status__exact=200)
        page_title_lookup_query &= Q(http_status__exact=200)

    url_lookup = EndPoint.objects.none()
    title_lookup = EndPoint.objects.none()

    if target:
        urls = EndPoint.objects.filter(target_domain__id=target).distinct('http_url')
        if url_lookup_query:
            url_lookup = urls.filter(url_lookup_query)
        if page_title_lookup_query:
            title_lookup = urls.filter(page_title_lookup_query)
    elif scan_history:
        urls = EndPoint.objects.filter(scan_history__id=scan_history)
        if url_lookup_query:
            url_lookup = urls.filter(url_lookup_query)
        if page_title_lookup_query:
            title_lookup = urls.filter(page_title_lookup_query)

    else:
        if url_lookup_query:
            url_lookup = EndPoint.objects.filter(url_lookup_query)
        if page_title_lookup_query:
            title_lookup = EndPoint.objects.filter(page_title_lookup_query)

    return url_lookup | title_lookup

def check_keyword_exists(keyword_list, subdomain):
    return any(sub in subdomain for sub in keyword_list)

def get_subdomain_from_url(url):
    extract_url = tldextract.extract(url)
    subdomain = '.'.join(extract_url[:4])
    if subdomain[0] == '.':
        subdomain = subdomain[1:]
    return subdomain.strip()

def get_domain_from_subdomain(subdomain):
    ext = tldextract.extract(subdomain)
    return '.'.join(ext[1:3])

def send_telegram_message(message):
    notification = Notification.objects.all()
    if notification and notification[0].send_to_telegram \
    and notification[0].telegram_bot_token \
    and notification[0].telegram_bot_chat_id:
        telegram_bot_token = notification[0].telegram_bot_token
        telegram_bot_chat_id = notification[0].telegram_bot_chat_id
        send_text = 'https://api.telegram.org/bot' + telegram_bot_token \
            + '/sendMessage?chat_id=' + telegram_bot_chat_id \
            + '&parse_mode=Markdown&text=' + message
        thread = Thread(target=requests.get, args = (send_text, ))
        thread.start()

def send_slack_message(message):
    headers = {'content-type': 'application/json'}
    message = {'text': message}
    notification = Notification.objects.all()
    if notification and notification[0].send_to_slack \
    and notification[0].slack_hook_url:
        hook_url = notification[0].slack_hook_url
        thread = Thread(
            target=requests.post,
            kwargs = {
                'url': hook_url,
                'data': json.dumps(message),
                'headers': headers,
            })
        thread.start()

def send_discord_message(message):
    notification = Notification.objects.all()
    if notification and notification[0].send_to_discord \
    and notification[0].discord_hook_url:
        webhook = DiscordWebhook(
            url=notification[0].discord_hook_url,
            content=message,
            rate_limit_retry=True
            )
        thread = Thread(target=webhook.execute)
        thread.start()

def send_files_to_discord(file_path):
    notification = Notification.objects.all()
    if notification and notification[0].send_to_discord \
    and notification[0].discord_hook_url:
        webhook = DiscordWebhook(
            url=notification[0].discord_hook_url,
            rate_limit_retry=True,
            username="Scan Results - File"
        )
        with open(file_path, "rb") as f:
            head, tail = os.path.split(file_path)
            webhook.add_file(file=f.read(), filename=tail)
        thread = Thread(target=webhook.execute)
        thread.start()

def send_notification(message):
    send_slack_message(message)
    send_discord_message(message)
    send_telegram_message(message)

def get_random_proxy():
    if Proxy.objects.all().exists():
        proxy = Proxy.objects.all()[0]
        if proxy.use_proxy:
            proxy_name = random.choice(proxy.proxies.splitlines())
            print('Using proxy: ' + proxy_name)
            return proxy_name
    return False

def send_hackerone_report(vulnerability_id):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    # get hackerone creds
    vulnerability = Vulnerability.objects.get(id=vulnerability_id)
    # can only send vulnerability report if team_handle exists
    if len(vulnerability.target_domain.h1_team_handle) !=0:
        if Hackerone.objects.all().exists():
            hackerone = Hackerone.objects.all()[0]
            if vulnerability.severity == 0:
                severity_value = 'none'
            elif vulnerability.severity == 1:
                severity_value = 'low'
            elif vulnerability.severity == 2:
                severity_value = 'medium'
            elif vulnerability.severity == 3:
                severity_value = 'high'
            elif vulnerability.severity == 4:
                severity_value = 'critical'
            report_template = hackerone.report_template
            # Replace syntax of report template with actual content
            if '{vulnerability_name}' in report_template:
                report_template = report_template.replace('{vulnerability_name}', vulnerability.name)
            if '{vulnerable_url}' in report_template:
                report_template = report_template.replace('{vulnerable_url}', vulnerability.http_url)
            if '{vulnerability_severity}' in report_template:
                report_template = report_template.replace('{vulnerability_severity}', severity_value)
            if '{vulnerability_description}' in report_template:
                report_template = report_template.replace('{vulnerability_description}', vulnerability.description if vulnerability.description else '')
            if '{vulnerability_extracted_results}' in report_template:
                report_template = report_template.replace('{vulnerability_extracted_results}', vulnerability.extracted_results if vulnerability.extracted_results else '')
            if '{vulnerability_reference}' in report_template:
                report_template = report_template.replace('{vulnerability_reference}', vulnerability.reference if vulnerability.reference else '')

            data = {
              "data": {
                "type": "report",
                "attributes": {
                  "team_handle": vulnerability.target_domain.h1_team_handle,
                  "title": '{} found in {}'.format(vulnerability.name, vulnerability.http_url),
                  "vulnerability_information": report_template,
                  "severity_rating": severity_value,
                  "impact": "More information about the impact and vulnerability can be found here: \n" + vulnerability.reference if vulnerability.reference else "NA",
                }
              }
            }

            r = requests.post(
              'https://api.hackerone.com/v1/hackers/reports',
              auth=(hackerone.username, hackerone.api_key),
              json = data,
              headers = headers
            )

            response = r.json()

            # print(response)

            status_code = r.status_code
            print(status_code)

            if status_code == 201:
                vulnerability.hackerone_report_id = response['data']["id"]
                vulnerability.open_status = False
                vulnerability.save()

            return status_code

    else:
        print('No target ')
        status_code = 111

        return status_code

def get_whois_using_domainbigdata(ip_domain, save_db=False, fetch_from_db=True):
    # CURRENTLY DEPRECATED!!!!!!
    # this function will fetch whois details for domains
    # if save_db = True, then the whois will be saved in db
    # if fetch_from_db = True then whois will be fetched from db, no lookup on
    #     bigdomain data will be done
    if ip_domain and not fetch_from_db:
        response = requests.get('https://domainbigdata.com/{}'.format(ip_domain))
        tree = html.fromstring(response.content)
        try:
            #RegistrantInfo Model
            name = tree.xpath('//*[@id="trRegistrantName"]/td[2]/a/text()')
            organization = tree.xpath('//*[@id="MainMaster_trRegistrantOrganization"]/td[2]/a/text()')
            email = tree.xpath('//*[@id="trRegistrantEmail"]/td[2]/a/text()')
            address = tree.xpath('//*[@id="trRegistrantAddress"]/td[2]/text()')
            city = tree.xpath('//*[@id="trRegistrantCity"]/td[2]/text()')
            state = tree.xpath('//*[@id="trRegistrantState"]/td[2]/text()')
            country = tree.xpath('//*[@id="trRegistrantCountry"]/td[2]/text()')
            country_iso = tree.xpath('//*[@id="imgFlagRegistrant"]/@alt')
            tel = tree.xpath('//*[@id="trRegistrantTel"]/td[2]/text()')
            fax = tree.xpath('//*[@id="trRegistrantFax"]/td[2]/text()')

            #finding domain association using organization
            organization_association_href = tree.xpath('//*[@id="MainMaster_trRegistrantOrganization"]/td[2]/a/@href')
            #finding domain association using email
            email_association_href = tree.xpath('//*[@id="trRegistrantEmail"]/td[2]/a/@href')

            # related tlds
            related_tlds = tree.xpath('//*[@id="divListOtherTLD"]/descendant::*/text()')

            # whois model
            whois = tree.xpath('//*[@id="whois"]/div/div[3]/text()')
            whois = "\n".join(whois).strip()

            # DomainInfo Model
            date_created = tree.xpath('//*[@id="trDateCreation"]/td[2]/text()')
            domain_age = tree.xpath('//*[@id="trWebAge"]/td[2]/text()')
            ip_address = tree.xpath('//*[@id="trIP"]/td[2]/a/text()')
            geolocation = tree.xpath('//*[@id="imgFlag"]/following-sibling::text()')
            geolocation_iso = tree.xpath('//*[@id="imgFlag"]/@alt')

            is_private_path = tree.xpath("//*[contains(@class, 'websiteglobalstats')]/tr[10]/td[2]/span/text()")
            is_private = False
            if len(is_private_path) > 0:
                is_private = True


            date_created = date_created[0].strip() if date_created else None
            domain_age = domain_age[0].strip() if domain_age else None
            ip_address = ip_address[0].strip() if ip_address else None
            geolocation = geolocation[0].strip() if geolocation else None
            geolocation_iso = geolocation_iso[0].strip() if geolocation_iso else None
            name = name[0].strip() if name else None
            organization = organization[0].strip() if organization else None
            email = email[0].strip() if email else None
            address = address[0].strip() if address else None
            city = city[0].strip() if city else None
            state = state[0].strip() if state else None
            country = country[0].strip() if country else None
            country_iso = country_iso[0].strip() if country_iso else None
            tel = tel[0].strip() if tel else None
            fax = fax[0].strip() if fax else None

            # association
            organization_association_href = organization_association_href[0].strip() if organization_association_href else None
            email_association_href = email_association_href[0].strip() if email_association_href else None

            # other tlds
            related_tlds = [ tld for tld in related_tlds if "\r\n" not in tld ]

            dns_history_xpath = tree.xpath("//*[@id='MainMaster_divNSHistory']/table/tbody/tr")
            dns_history = []
            for table_row in dns_history_xpath:
                row = table_row.xpath('td/text()')
                dns_history.append(
                    {
                        'date': row[0],
                        'action': row[1],
                        'nameserver': row[2],
                    }
                )

            associated_domains = []
            if organization_association_href and organization not in IGNORE_WHOIS_RELATED_KEYWORD:
                # get all associated domains using organization
                response_org = requests.get('https://domainbigdata.com{}'.format(organization_association_href))
                tree_org = html.fromstring(response_org.content)
                associated_domains_tree = tree_org.xpath('//*[@id="aDomain"]/text()')
                for domain in associated_domains_tree:
                    associated_domains.append(domain)

            if email_association_href and email not in IGNORE_WHOIS_RELATED_KEYWORD:
                print(email_association_href)
                response_email = requests.get('https://domainbigdata.com{}'.format(email_association_href))
                tree_email = html.fromstring(response_email.content)
                associated_domains_tree = tree_email.xpath('//*[@id="aDomain"]/text()')
                for domain in associated_domains_tree:
                    associated_domains.append(domain)

            # unique associated_domains
            unique_associated_domains = []
            [unique_associated_domains.append(domain) for domain in associated_domains if domain not in unique_associated_domains]

            # Save domain in db
            if save_db and Domain.objects.filter(name=ip_domain).exists():
                domain = Domain.objects.get(name=ip_domain)
                if RegistrantInfo.objects.filter(email=email).filter(name=name).exists():
                    registrant = RegistrantInfo.objects.get(email=email, name=name)
                else:
                    registrant = RegistrantInfo()
                    registrant.name = name
                    registrant.organization = organization
                    registrant.email = email
                    registrant.address = address
                    registrant.city = city
                    registrant.state = state
                    registrant.country = country
                    registrant.country_iso = country_iso
                    registrant.phone_number = tel
                    registrant.fax = fax
                    registrant.organization_association_href = organization_association_href
                    registrant.email_association_href = email_association_href
                    registrant.save()

                if WhoisDetail.objects.filter(details=whois).exists():
                    whois_model = WhoisDetail.objects.get(details=whois)
                else:
                    whois_model = WhoisDetail()
                    whois_model.details = whois if whois else None
                    whois_model.registrant = registrant
                    whois_model.save()

                domain_info = DomainInfo()
                domain_info.date_created = date_created
                domain_info.domain_age = domain_age
                domain_info.ip_address = ip_address
                domain_info.geolocation = geolocation
                domain_info.geolocation_iso = geolocation_iso
                domain_info.whois = whois_model
                domain_info.save()

                for table_row in dns_history_xpath:
                    row = table_row.xpath('td/text()')
                    ns_history = NameServerHistory()
                    ns_history.date = row[0]
                    ns_history.action = row[1]
                    ns_history.server = row[2]
                    ns_history.save()

                    domain_info.nameserver_history.add(ns_history);

                domain.domain_info = domain_info
                domain.save()


                # save associated domains
                for domain in unique_associated_domains:
                    if AssociatedDomain.objects.filter(name=domain).exists():
                        ass_domain = AssociatedDomain.objects.get(name=domain)
                    else:
                        ass_domain = AssociatedDomain()
                        ass_domain.name = domain
                        ass_domain.save()
                    domain_info.associated_domains.add(ass_domain)

                # save related TLDs
                for tld in related_tlds:
                    if RelatedTLD.objects.filter(name=tld).exists():
                        rel_tld = RelatedTLD.objects.get(name=tld)
                    else:
                        rel_tld = RelatedTLD()
                        rel_tld.name = tld
                        rel_tld.save()
                    domain_info.related_tlds.add(rel_tld)

            ns_records = []
            for i in range(4):
                ns_records_xpath = tree.xpath("//*[@id='divDNSRecords']/table[{}]/tbody/tr".format(i))
                for table_row in ns_records_xpath:
                    row = table_row.xpath('td/text()')
                    if row[0] == 'A':
                        # for getting address, use child lookup
                        address = table_row.xpath('td/a/text()')
                        address = address[0] if address else None

                        ns_records.append(
                            {
                                'type': row[0],
                                'hostname': row[1],
                                'address': address,
                                'ttl': row[2],
                                'class': row[3],
                            }
                        )

                        if save_db and Domain.objects.filter(name=ip_domain).exists():
                            ns = NSRecord()
                            ns.type = row[0]
                            ns.hostname = row[1]
                            ns.address = address
                            ns.ttl = row[2]
                            ns.ns_class = row[3]
                            ns.save()
                            domain_info.nameserver_record.add(ns)

                    elif row[0] == 'AAAA':
                        # for getting address, use child lookup
                        ns_records.append(
                            {
                                'type': row[0],
                                'hostname': row[1],
                                'address': row[2],
                                'ttl': row[3],
                                'class': row[4],
                            }
                        )

                        if save_db and Domain.objects.filter(name=ip_domain).exists():
                            ns = NSRecord()
                            ns.type = row[0]
                            ns.hostname = row[1]
                            ns.address = row[2]
                            ns.ttl = row[3]
                            ns.ns_class = row[4]
                            ns.save()
                            domain_info.nameserver_record.add(ns)

                    elif row[0] == 'MX':
                        ns_records.append(
                            {
                                'type': row[0],
                                'hostname': row[1],
                                'address': row[2],
                                'preference': row[3],
                                'ttl': row[4],
                                'class': row[5],
                            }
                        )

                        if save_db and Domain.objects.filter(name=ip_domain).exists():
                            ns = NSRecord()
                            ns.type = row[0]
                            ns.hostname = row[1]
                            ns.address = address
                            ns.preference = row[3]
                            ns.ttl = row[4]
                            ns.ns_class = row[5]
                            ns.save()
                            domain_info.nameserver_record.add(ns)


            final_organization_association_url = 'https://domainbigdata.com' + organization_association_href if organization_association_href else None
            final_email_association_url = 'https://domainbigdata.com' + email_association_href if email_association_href else None


            return {
                'status': True,
                'ip_domain': ip_domain,
                'domain': {
                    'date_created': date_created,
                    'domain_age': domain_age,
                    'ip_address': ip_address,
                    'geolocation': geolocation,
                    'geolocation_iso': geolocation_iso,
                },
                'nameserver': {
                    'history': dns_history,
                    'records': ns_records
                },
                'registrant': {
                    'name': name,
                    'organization': organization,
                    'email': email,
                    'address': address,
                    'city': city,
                    'state': state,
                    'country': country,
                    'country_iso': country_iso,
                    'tel': tel,
                    'fax': fax,
                    'organization_association_url': final_organization_association_url,
                    'email_association_url': final_email_association_url,
                },
                'related_domains': unique_associated_domains,
                'related_tlds': related_tlds,
                'whois': whois if whois else None
            }
        except Exception as e:
            logging.exception(e)
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': 'Domain not found'
            }
    elif ip_domain and fetch_from_db:
        if Domain.objects.filter(name=ip_domain).exists():
            domain = Domain.objects.get(name=ip_domain)
            unique_associated_domains = []

            if domain.domain_info and domain.domain_info.associated_domains:
                unique_associated_domains = [d.name for d in domain.domain_info.associated_domains.all()]


            unique_related_tlds = []
            if domain.domain_info and domain.domain_info.related_tlds:
                unique_related_tlds = [d.name for d in domain.domain_info.related_tlds.all()]

            if domain.domain_info:
                return {
                    'status': True,
                    'ip_domain': ip_domain,
                    'domain': {
                        'date_created': domain.domain_info.date_created,
                        'domain_age': domain.domain_info.domain_age,
                        'ip_address': domain.domain_info.ip_address,
                        'geolocation': domain.domain_info.geolocation,
                        'geolocation_iso': domain.domain_info.geolocation_iso,
                    },
                    'nameserver': {
                        'history': NameServerHistorySerializer(domain.domain_info.nameserver_history.all(), many=True).data,
                        'records': NSRecordSerializer(domain.domain_info.nameserver_record.all(), many=True).data
                    },
                    'registrant': {
                        'name': domain.domain_info.whois.registrant.name,
                        'organization': domain.domain_info.whois.registrant.organization,
                        'email': domain.domain_info.whois.registrant.email,
                        'address': domain.domain_info.whois.registrant.address,
                        'city': domain.domain_info.whois.registrant.city,
                        'state': domain.domain_info.whois.registrant.state,
                        'country': domain.domain_info.whois.registrant.country,
                        'country_iso': domain.domain_info.whois.registrant.country_iso,
                        'tel': domain.domain_info.whois.registrant.phone_number,
                        'fax': domain.domain_info.whois.registrant.fax,
                    },
                    'related_domains': unique_associated_domains,
                    'related_tlds': unique_related_tlds,
                    'whois': domain.domain_info.whois.details
                }
            return {
                'status': False,
                'message': 'WHOIS does not exist.'
            }
        return {
            'status': False,
            'message': 'Domain ' + ip_domain + ' does not exist as target and could not fetch WHOIS from database.'
        }

def calculate_age(created):
    today = date.today()
    return today.year - created.year - ((today.month, today.day) < (created.month, created.day))

def return_zeorth_if_list(variable):
    return variable[0] if type(variable) == list else variable

def get_whois(ip_domain, save_db=False, fetch_from_db=True):
    if not fetch_from_db:
        result = asyncwhois.whois_domain(ip_domain)
        whois = result.parser_output
        if not whois.get('domain_name'):
            return {
                'status': False,
                'ip_domain': ip_domain,
                'result': 'Unable to fetch records from WHOIS database.'
            }
        created = whois.get('created')
        expires = whois.get('expires')
        updated = whois.get('updated')
        dnssec = whois.get('dnssec')

        # Save whois information in various tables
        domain_query = Domain.objects.filter(name=ip_domain)
        if save_db and domain_query.exists():
            domain = domain_query.first()
            logger.info(f'Saving domain "{domain}" info in DB!')
            domain_info = DomainInfo()
            domain_info.raw_text = result.query_output.strip()
            domain_info.dnsec = dnssec
            domain_info.created = created
            domain_info.updated = updated
            domain_info.expires = expires

            # Record whois subfields in various DB models
            whois_fields = {
                ('default'): [
                    ('registrar', DomainRegistrar),
                    ('name_servers', NameServers)
                ],
                ('registrant'):
                    [
                        ('name', DomainRegisterName),
                        ('organization', DomainRegisterOrganization),
                        ('address', DomainAddress),
                        ('city', DomainCity),
                        ('state', DomainState),
                        ('zipcode', DomainZipCode),
                        ('country', DomainCountry),
                        ('phone', DomainPhone),
                        ('fax', DomainFax),
                        ('email', DomainEmail)
                    ],
                ('admin', 'tech'): [
                    ('name', DomainRegisterName),
                    ('id', DomainRegistrarID),
                    ('organization', DomainRegisterOrganization),
                    ('address', DomainAddress),
                    ('city', DomainCity),
                    ('state', DomainState),
                    ('zipcode', DomainZipCode),
                    ('country', DomainCountry),
                    ('email', DomainEmail),
                    ('phone', DomainPhone),
                    ('fax', DomainFax)
                ]
            }
            objects = {}
            logger.info(f'Gathering domain details for {ip_domain}...')
            for field_parents, fields in whois_fields.items():
                for field_parent in field_parents:
                    for (field_name, model_cls) in fields:
                        field_fullname = f'{field_parent}_{field_name}' if field_parent != 'default' else field_name
                        field_content = whois.get(field_fullname)
                        serializer_cls = globals()[model_cls.__name__ + 'Serializer']

                        # If field is an email, parse it with a regex
                        if field_name == 'email':
                            email_search = EMAIL_REGEX.search(str(field_content))
                            field_content = email_search.group(0) if email_search else None

                        # Skip empty fields
                        if not field_content:
                            continue

                        # Create object in database
                        obj, created = model_cls.objects.get_or_create(name=field_content)
                        obj_json = serializer_cls(obj, many=False).data
                        objects[field_fullname] = obj_json
                        if created:
                            logger.info(f'Saved {obj} in DB !')

                        # Set attribute in domain_info
                        setattr(domain_info, field_fullname, obj)
                        domain_info.save()

            logger.info(f'Finished saving domain info {ip_domain}.')

            # Whois status
            whois_status = whois.get('status', [])
            for _status in whois_status:
                domain_whois, _ = DomainWhoisStatus.objects.get_or_create(status=_status)
                domain_info.status.add(domain_whois)
                domain_whois_json = DomainWhoisStatusSerializer(domain_whois, many=False).data
                if 'whois_status' in objects:
                    objects['whois_status'].append(domain_whois_json)
                else:
                    objects['whois_status'] = [domain_whois_json]

            # Nameservers
            nameservers = whois.get('name_servers', [])
            for name_server in nameservers:
                ns, _ = NameServers.objects.get_or_create(name=name_server)
                domain_info.name_servers.add(ns)
                ns_json = NameServersSerializer(ns, many=False).data
                if 'name_servers' in objects:
                    objects['name_servers'].append(ns_json)
                else:
                    objects['name_servers'] = [ns_json]

            # Save domain in DB
            domain.domain_info = domain_info
            domain.save()

            return {
                'status': True,
                'ip_domain': ip_domain,
                'domain': {
                    'created': created,
                    'updated': updated,
                    'expires': expires,
                    'registrar': domain_info.registrar,
                    'geolocation_iso': objects[('registrant')]['country'],
                    'dnssec': dnssec,
                    'status': _status,
                },
                'registrant': objects[('registrant')],
                'admin': objects['admin'],
                'technical_contact': objects['tech'],
                'nameservers': objects['name_servers'],
                'raw_text': result.query_output.strip()
            }

    else:
        domain = Domain.objects.get(name=ip_domain) if Domain.objects.filter(name=ip_domain).exists() else None
        if not domain:
            return {
                'status': False,
                'message': 'Domain ' + ip_domain + ' does not exist as target and could not fetch WHOIS from database.'
            }

        if not domain.domain_info:
            return {
                'status': False,
                'message': 'WHOIS could not be fetched!'
            }

        return {
            'status': True,
            'ip_domain': ip_domain,
            'domain': {
                'created': domain.domain_info.created,
                'updated': domain.domain_info.updated,
                'expires': domain.domain_info.expires,
                'registrar': DomainRegistrarSerializer(domain.domain_info.registrar).data['name'],
                'geolocation_iso': DomainCountrySerializer(domain.domain_info.registrant_country).data['name'],
                'dnssec': domain.domain_info.dnssec,
                'status': [status['status'] for status in DomainWhoisStatusSerializer(domain.domain_info.status, many=True).data]
            },
            'registrant': {
                'name': DomainRegisterNameSerializer(domain.domain_info.registrant_name).data['name'],
                'organization': DomainRegisterOrganizationSerializer(domain.domain_info.registrant_organization).data['name'],
                'address': DomainAddressSerializer(domain.domain_info.registrant_address).data['name'],
                'city': DomainCitySerializer(domain.domain_info.registrant_city).data['name'],
                'state': DomainStateSerializer(domain.domain_info.registrant_state).data['name'],
                'zipcode': DomainZipCodeSerializer(domain.domain_info.registrant_zip_code).data['name'],
                'country': DomainCountrySerializer(domain.domain_info.registrant_country).data['name'],
                'phone': DomainPhoneSerializer(domain.domain_info.registrant_phone).data['name'],
                'fax': DomainFaxSerializer(domain.domain_info.registrant_fax).data['name'],
                'email': DomainEmailSerializer(domain.domain_info.registrant_email).data['name'],
            },
            'admin': {
                'name': DomainRegisterNameSerializer(domain.domain_info.admin_name).data['name'],
                'id': DomainRegistrarIDSerializer(domain.domain_info.admin_id).data['name'],
                'organization': DomainRegisterOrganizationSerializer(domain.domain_info.admin_organization).data['name'],
                'address': DomainAddressSerializer(domain.domain_info.admin_address).data['name'],
                'city': DomainCitySerializer(domain.domain_info.admin_city).data['name'],
                'state': DomainStateSerializer(domain.domain_info.admin_state).data['name'],
                'zipcode': DomainZipCodeSerializer(domain.domain_info.admin_zip_code).data['name'],
                'country': DomainCountrySerializer(domain.domain_info.admin_country).data['name'],
                'phone': DomainPhoneSerializer(domain.domain_info.admin_phone).data['name'],
                'fax': DomainFaxSerializer(domain.domain_info.admin_fax).data['name'],
                'email': DomainEmailSerializer(domain.domain_info.admin_email).data['name'],
            },
            'technical_contact': {
                'name': DomainRegisterNameSerializer(domain.domain_info.tech_name).data['name'],
                'id': DomainRegistrarIDSerializer(domain.domain_info.tech_id).data['name'],
                'organization': DomainRegisterOrganizationSerializer(domain.domain_info.tech_organization).data['name'],
                'address': DomainAddressSerializer(domain.domain_info.tech_address).data['name'],
                'city': DomainCitySerializer(domain.domain_info.tech_city).data['name'],
                'state': DomainStateSerializer(domain.domain_info.tech_state).data['name'],
                'zipcode': DomainZipCodeSerializer(domain.domain_info.tech_zip_code).data['name'],
                'country': DomainCountrySerializer(domain.domain_info.tech_country).data['name'],
                'phone': DomainPhoneSerializer(domain.domain_info.tech_phone).data['name'],
                'fax': DomainFaxSerializer(domain.domain_info.tech_fax).data['name'],
                'email': DomainEmailSerializer(domain.domain_info.tech_email).data['name'],
            },
            'nameservers': [ns['name'] for ns in NameServersSerializer(domain.domain_info.name_servers, many=True).data],
            'raw_text': domain.domain_info.raw_text
        }


def get_cms_details(url):
    # this function will fetch cms details using cms_detector
    response = {}
    cms_detector_command = 'python3 /usr/src/github/CMSeeK/cmseek.py --random-agent --batch --follow-redirect'
    subprocess_splitted_command = cms_detector_command.split()
    subprocess_splitted_command.append('-u')
    subprocess_splitted_command.append(url)
    process = subprocess.Popen(subprocess_splitted_command)
    process.wait()

    response['status'] = False
    response['message'] = 'Could not detect CMS!'

    parsed_url = urlparse(url)

    domain_name = parsed_url.hostname
    port = parsed_url.port

    find_dir = domain_name

    if port:
        find_dir += '_{}'.format(port)

    # subdomain may also have port number, and is stored in dir as _port

    cms_dir_path =  '/usr/src/github/CMSeeK/Result/{}'.format(find_dir)
    cms_json_path =  cms_dir_path + '/cms.json'

    if os.path.isfile(cms_json_path):
        cms_file_content = json.loads(open(cms_json_path, 'r').read())
        if not cms_file_content.get('cms_id'):
            return response
        response = {}
        response = cms_file_content
        response['status'] = True
        # remove cms dir path
        try:
            shutil.rmtree(cms_dir_path)
        except Exception as e:
            print(e)

    return response


def remove_cmd_injection_chars(command):
    remove_chars = ['&', '<', '>', '|', ';', '$', '`']
    for chrs in remove_chars:
        command = command.replace(chrs, '')
    return command
