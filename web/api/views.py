import re
import json
import logging
import requests
import subprocess
import validators
import csv
import io
import ipaddress
from bs4 import BeautifulSoup
from lxml import html

# selenium
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from datetime import timedelta
from django.utils import timezone
from django.db.models.functions import TruncDay
from django.db.models.functions import Trunc, Concat

from django.db.models import Q, F
from django.db.models import CharField, Value, Count
from django.core import serializers
from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, action
from rest_framework import generics

from reNgine.common_func import *

from .serializers import *
from scanEngine.models import *
from startScan.models import *
from dashboard.models import *
from targetApp.models import *
from recon_note.models import *

from reNgine.utilities import is_safe_path
from reNgine.tasks import run_system_commands, initiate_subtask, create_scan_activity
from packaging import version
from reNgine.celery import app
from django.utils import timezone


from django.db.models import Count
from django.db.models.functions import TruncMonth
from django.db.models import CharField, Value
from django.db.models.functions import Concat

from datetime import datetime, timedelta
from urllib.parse import urlparse


def get_ip_info(ip_address):
    is_ipv4 = bool(validators.ipv4(ip_address))
    is_ipv6 = bool(validators.ipv6(ip_address))
    ip_data = None
    if is_ipv4:
        ip_data = ipaddress.IPv4Address(ip_address)
    elif is_ipv6:
        ip_data = ipaddress.IPv6Address(ip_address)
    else:
        return None
    return ip_data


def get_ips_from_cidr_range(target):
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(target)]
    except Exception as e:
        logger.error(f"{target} is not a valid CIDR range. Skipping.")


class AddTarget(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        print(data, "trdata")
        context = {"status": False}

        org_instance = Organization.objects.get(id=data["org_id"])

        added_target_count = 0
        multiple_targets = data.get("addTargets")
        description = data.get("targetDescription", "")
        h1_team_handle = data.get("targetH1TeamHandle", "")

        try:
            # Multiple targets
            # if multiple_targets:
            bulk_targets = [t.rstrip() for t in multiple_targets.split(",") if t]
            logging.info(f"Adding multiple targets: {bulk_targets}")
            for target in bulk_targets:
                target = target.rstrip("\n")
                http_urls = []
                domains = []
                ports = []
                ips = []

                # Validate input and find what type of address it is.
                # Valid inputs are URLs, Domains, or IP addresses.
                # TODO: support IP CIDR ranges (auto expand range and
                # save new found ips to DB)
                is_domain = bool(validators.domain(target))
                is_ip = bool(validators.ipv4(target)) or bool(validators.ipv6(target))
                is_range = bool(validators.ipv4_cidr(target)) or bool(
                    validators.ipv6_cidr(target)
                )
                is_url = bool(validators.url(target))

                # Set ip_domain / http_url based on type of input
                logging.info(
                    f"{target} | Domain? {is_domain} | IP? {is_ip} | CIDR range? {is_range} | URL? {is_url}"
                )

                if is_domain:
                    domains.append(target)

                elif is_url:
                    url = urlparse(target)
                    http_url = url.geturl()
                    http_urls.append(http_url)
                    split = url.netloc.split(":")
                    if len(split) == 1:
                        domain = split[0]
                        domains.append(domain)
                    if len(split) == 2:
                        domain, port_number = tuple(split)
                        domains.append(domain)
                        ports.append(port_number)

                elif is_ip:
                    ips.append(target)
                    domains.append(target)

                elif is_range:
                    ips = get_ips_from_cidr_range(target)
                    for ip_address in ips:
                        ips.append(ip_address)
                        domains.append(ip_address)
                else:
                    msg = f"{target} is not a valid domain, IP, or URL. Skipped."
                    logging.info(msg)
                    continue

                logging.info(
                    f"IPs: {ips} | Domains: {domains} | URLs: {http_urls} | Ports: {ports}"
                )

                for domain_name in domains:
                    if not Domain.objects.filter(name=domain_name).exists():
                        domain, created = Domain.objects.get_or_create(
                            name=domain_name,
                            description=description,
                            h1_team_handle=h1_team_handle,
                            # project=project,
                            insert_date=timezone.now(),
                            ip_address_cidr=domain_name if is_ip else None,
                        )
                        # domain.save()
                        org_instance.domains.add(domain)
                        added_target_count += 1
                        if created:
                            logging.info(f"Added new domain {domain.name}")

                for http_url in http_urls:
                    http_url = sanitize_url(http_url)
                    endpoint, created = EndPoint.objects.get_or_create(
                        target_domain=domain, http_url=http_url
                    )
                    if created:
                        logging.info(f"Added new endpoint {endpoint.http_url}")

                for ip_address in ips:
                    ip_data = get_ip_info(ip_address)
                    ip, created = IpAddress.objects.get_or_create(address=ip_address)
                    ip.reverse_pointer = ip_data.reverse_pointer
                    ip.is_private = ip_data.is_private
                    ip.version = ip_data.version
                    ip.save()
                    if created:
                        logging.info(f"Added new IP {ip}")

                for port in ports:
                    port, created = Port.objects.get_or_create(number=port_number)
                    if created:
                        logging.info(f"Added new port {port.number}.")
        except Exception as e:
            logging.info(e)
            context["desc"] = f"Exception while adding domain: {e}"
            return Response(context)

        # No targets added, redirect to add target page
        if added_target_count == 0:
            context[
                "desc"
            ] = f"Oops! Could not import any targets, either targets already exists or is not a valid target."
            return Response(context)

        # Targets added successfully, redirect to targets list
        msg = f"{added_target_count} targets added successfully"
        context["status"] = True
        context["desc"] = msg
        return Response(context)

    # target_name = data.get("domain_name")
    # h1_team_handle = data.get("h1_team_handle")
    # description = data.get("description")
    # ip_address = data.get("ip_address")

    # if not target_name:
    #     return Response({"status": False, "message": "domain_name missing!"})

    # # validate if target_name is a valid domain_name
    # if not validators.domain(target_name):
    #     return Response({"status": False, "message": "Invalid Domain or IP"})

    # org_instance = Organization.objects.get(id=data["org_id"])
    # print(org_instance, "oiiins")
    # if Domain.objects.filter(name=target_name).exists():
    #     domain = Domain.objects.get(name=target_name)
    #     if ip_address:
    #         domain.ip_address_cidr = ip_address
    #     domain.save()
    #     org_instance.domains.add(domain)
    #     return Response(
    #         {
    #             "status": False,
    #             "message": "Target already exists!",
    #             "domain_id": domain.id,
    #         }
    #     )

    # domain = Domain()
    # domain.description = description
    # domain.name = target_name
    # domain.insert_date = timezone.now()
    # domain.h1_team_handle = h1_team_handle

    # if ip_address:
    #     domain.ip_address_cidr = ip_address
    # domain.save()
    # org_instance.domains.add(domain)

    # return Response(
    #     {
    #         "status": True,
    #         "message": "Domain successfully added as target!",
    #         "domain_name": target_name,
    #         "domain_id": domain.id,
    #     }
    # )


class AddOrganization(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        print(data["name"], data["desc"], "aat")
        response = {}
        response["status"] = False
        try:
            org = Organization.objects.get(name=data["name"])
            response["desc"] = "Organization name not available"
            return Response(response)
        except Organization.DoesNotExist:
            notification = Notification()
            notification.save()
            organization = Organization(
                name=data["name"],
                description=data["desc"],
                insert_date=timezone.now(),
                notification=notification,
            )
            organization.save()
            print(organization.pk, "org")
            response["status"] = True
            response["org_id"] = organization.id
            return Response(response)


from login_required import login_not_required
from django.contrib.auth import authenticate, login, logout
from django.forms.models import model_to_dict
from django.core import serializers
from django.middleware.csrf import get_token


def serialize_(qs):
    return serializers.serialize("json", qs)


@login_not_required
class loginview(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        req = self.request
        data = req.data
        print(data, "data")
        context = {}
        user = authenticate(
            request,
            username=data["username"],
            password=data["password"],
        )
        print(user)
        context["user"] = model_to_dict(user)
        if user:
            csrf_token = get_token(request)
            loggedIn = login(request, user)

            context["loggedIn"] = loggedIn
            context["csrf_token"] = csrf_token

            return Response(context)
        return Response(context)


class logoutview(APIView):
    def get(self, request):
        logout(request)
        return Response({"status": True})


class NotificationAPi(APIView):
    def get(self, request):
        org_id = request.query_params.get("org_id")
        kr = Organization.objects.select_related("notification").get(id=org_id)
        og = Notification.objects.get(
            id=list(
                Organization.objects.filter(id=org_id).values_list(
                    "notification", flat=True
                )
            )[0]
        )
        print(
            og, kr.notification.send_to_slack, kr.notification.send_to_telegram, "dgg"
        )
        notn_obj = model_to_dict(kr.notification)
        return Response({"obj": notn_obj})

    def post(self, request):
        req = self.request
        data = req.data
        context = {}

        org_id = req.query_params.get("org_id")

        send_to_slack = data.get("send_to_slack", None)
        send_to_discord = data.get("send_to_discord", None)
        send_to_telegram = data.get("send_to_telegram", None)
        slack_hook_url = data.get("slack_hook_url", None)
        discord_hook_url = data.get("discord_hook_url", None)
        telegram_bot_token = data.get("telegram_bot_token", None)
        telegram_bot_chat_id = data.get("telegram_bot_chat_id", None)
        send_scan_status_notif = data.get("send_scan_status_notif", None)
        send_interesting_notif = data.get("send_interesting_notif", None)
        send_vuln_notif = data.get("send_vuln_notif", None)
        send_subdomain_changes_notif = data.get("send_subdomain_changes_notif", None)
        send_scan_output_file = data.get("send_scan_output_file", None)

        update = {}

        if send_to_slack != None:
            update["send_to_slack"] = send_to_slack
        if send_to_discord != None:
            update["send_to_discord"] = send_to_discord
        if send_to_telegram != None:
            update["send_to_telegram"] = send_to_telegram
        if slack_hook_url != None:
            update["slack_hook_url"] = slack_hook_url
        if discord_hook_url != None:
            update["discord_hook_url"] = discord_hook_url
        if telegram_bot_token != None:
            update["telegram_bot_token"] = telegram_bot_token
        if telegram_bot_chat_id != None:
            update["telegram_bot_chat_id"] = telegram_bot_chat_id
        if send_scan_status_notif != None:
            update["send_scan_status_notif"] = send_scan_status_notif
        if send_interesting_notif != None:
            update["send_interesting_notif"] = send_interesting_notif
        if send_vuln_notif != None:
            update["send_vuln_notif"] = send_vuln_notif
        if send_subdomain_changes_notif != None:
            update["send_subdomain_changes_notif"] = send_subdomain_changes_notif
        if send_scan_output_file != None:
            update["send_scan_output_file"] = send_scan_output_file
        print(update, "gee")
        try:
            og = list(
                Organization.objects.filter(id=org_id)
                .select_related("notification")
                .all()
                .values_list("notification__id", flat=True)
            )
            print(og, "dgg")
            notn_obj = Notification.objects.filter(id=og[0]).update(**update)
            print(notn_obj, "newio")

            return Response({"status": True})
        except Exception as e:
            return Response({"status": str(e)})


import pickle
import json


class Dashboard(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        orgId = data["org_id"]
        try:
            domain_ = Organization.objects.get(id=orgId).get_domains()

            # ------------------------------------------

            sd_analysis = (
                domain_.prefetch_related("subdomain")
                .annotate(month=TruncMonth("subdomain__discovered_date"))
                .values("month")
                .annotate(total=Count("subdomain"))
                .values()
            )
            ip_analysis = (
                domain_.prefetch_related("subdomain__ip_addresses")
                .annotate(month=TruncMonth("subdomain__discovered_date"))
                .values("month")
                .annotate(total=Count("subdomain__ip_addresses"))
                .values()
            )
            vul_analysis = (
                domain_.prefetch_related("vulnerability")
                .annotate(month=TruncMonth("vulnerability__discovered_date"))
                .values("month")
                .annotate(total=Count("vulnerability"))
                .values()
            )

            port_analysis = (
                domain_.prefetch_related("subdomain__ip_addresses__ports")
                .annotate(month=TruncMonth("subdomain__discovered_date"))
                .values("month")
                .annotate(total=Count("subdomain__ip_addresses__ports__number"))
                .values()
            )

            org_domain = list(domain_.values_list("id", flat=True))

            # ------------------------------------------

            # eg_ple = list(Domain.objects.filter(id=6).values_list("domain_info", flat=True))
            # print(eg_ple, "true")

            org_subdomain = Subdomain.objects.filter(target_domain__pk__in=org_domain)
            org_subdomain_id = list(org_subdomain.values_list("id", flat=True))

            org_scan_history = ScanHistory.objects.filter(
                domain__pk__in=org_domain
            ).annotate(month=TruncMonth("start_scan_date"))
            org_scan_id = list(org_scan_history.values_list("id", flat=True))

            # org_scan_months = org_scan_history.group_by()
            org_ip_over_months = (
                org_scan_history.prefetch_related("subdomain_set")
                .all()
                .order_by("month")
            )
            print(org_ip_over_months.first().subdomain_set.all(), "org_ip_over_months")

            lastest_scan = org_scan_history.order_by("-start_scan_date").first()
            print(lastest_scan, "scllaa")

            org_sub_scan = SubScan.objects.filter(scan_history__pk__in=org_scan_id)
            org_sub_scan_id = list(org_sub_scan.values_list("id", flat=True))

            org_ip = IpAddress.objects.filter(ip_subscan_ids__id__in=org_sub_scan_id)
            org_ip_id = list(org_ip.values_list("id", flat=True))

            # ctr_iso = CountryISO.objects.filter(id__in=org_sub_scan_id)
            # ctr_iso_id = org_ip.values_list("geo_iso", flat=True)
            ctr_iso_id = list(org_ip.values_list("geo_iso", flat=True))
            print(ctr_iso_id, "cts")

            domain_count = Domain.objects.filter(id__in=org_domain).count()
            endpoint = EndPoint.objects.filter(target_domain__pk__in=org_domain)
            endpoint_count = endpoint.count()
            scan_count = org_scan_history.count()
            subdomain_count = Subdomain.objects.filter(
                target_domain__pk__in=org_domain
            ).count()
            subdomain_with_ip_count = Subdomain.objects.filter(
                target_domain__pk__in=org_domain, ip_addresses__isnull=False
            ).count()
            alive_count = (
                Subdomain.objects.filter(target_domain__pk__in=org_domain)
                .exclude(http_status__exact=0)
                .count()
            )
            endpoint_alive_count = EndPoint.objects.filter(
                target_domain__pk__in=org_domain, http_status__exact=200
            ).count()

            vulnerabilities = Vulnerability.objects.filter(
                target_domain__pk__in=org_domain
            )

            vul_ports = (
                vulnerabilities.prefetch_related("subdomain__ip_addresses__ports")
                .values("subdomain__ip_addresses__ports__number")
                .annotate(
                    vuln_ports_group=Concat(
                        "severity",
                        "subdomain__ip_addresses__ports__number",
                        output_field=models.CharField(),
                    )
                )
                .annotate(vcount=models.Count("vuln_ports_group"))
                .values()
            )
            print(vul_ports, "sojal")

            latest_vulnerabilities = list(
                vulnerabilities.filter(scan_history=lastest_scan)
                .values("severity")
                .annotate(count=Count("severity"))
            )

            vulnerabilities_id = list(vulnerabilities.values_list("id", flat=True))

            info_count = vulnerabilities.filter(severity=0).count()
            low_count = vulnerabilities.filter(severity=1).count()
            medium_count = vulnerabilities.filter(severity=2).count()
            high_count = vulnerabilities.filter(severity=3).count()
            critical_count = vulnerabilities.filter(severity=4).count()
            unknown_count = vulnerabilities.filter(severity=-1).count()

            vulnerability_feed = Vulnerability.objects.filter(
                target_domain__pk__in=org_domain
            ).order_by("-discovered_date")[:20]
            activity_feed = (
                ScanActivity.objects.filter(scan_of__pk__in=org_scan_id)
                .order_by("-time")
                .values()[:20]
            )
            total_vul_count = (
                info_count
                + low_count
                + medium_count
                + high_count
                + critical_count
                + unknown_count
            )
            total_vul_ignore_info_count = (
                low_count + medium_count + high_count + critical_count
            )
            most_common_vulnerability = (
                Vulnerability.objects.filter(target_domain__pk__in=org_domain)
                .values("name", "severity")
                .annotate(count=Count("name"))
                .order_by("-count")
                .values()[:10]
            )
            last_week = timezone.now() - timedelta(days=7)

            count_targets_by_date = (
                Domain.objects.filter(id__in=org_domain, insert_date__gte=last_week)
                .annotate(date=TruncDay("insert_date"))
                .values("date")
                .annotate(created_count=Count("id"))
                .order_by("-date")
                .values()
            )
            count_subdomains_by_date = (
                Subdomain.objects.filter(
                    target_domain__pk__in=org_domain, discovered_date__gte=last_week
                )
                .annotate(date=TruncDay("discovered_date"))
                .values("date")
                .annotate(count=Count("id"))
                .order_by("-date")
                .values()
            )
            count_vulns_by_date = (
                Vulnerability.objects.filter(
                    target_domain__pk__in=org_domain, discovered_date__gte=last_week
                )
                .annotate(date=TruncDay("discovered_date"))
                .values("date")
                .annotate(count=Count("id"))
                .order_by("-date")
                .values()
            )
            count_scans_by_date = (
                ScanHistory.objects.filter(
                    domain__pk__in=org_domain, start_scan_date__gte=last_week
                )
                .annotate(date=TruncDay("start_scan_date"))
                .values("date")
                .annotate(count=Count("id"))
                .order_by("-date")
                .values()
            )
            count_endpoints_by_date = (
                EndPoint.objects.filter(
                    target_domain__pk__in=org_domain, discovered_date__gte=last_week
                )
                .annotate(date=TruncDay("discovered_date"))
                .values("date")
                .annotate(count=Count("id"))
                .order_by("-date")
                .values()
            )

            last_7_dates = [
                (timezone.now() - timedelta(days=i)).date() for i in range(0, 7)
            ]

            targets_in_last_week = []
            subdomains_in_last_week = []
            vulns_in_last_week = []
            scans_in_last_week = []
            endpoints_in_last_week = []

            for date in last_7_dates:
                _target = count_targets_by_date.filter(date=date)
                _subdomain = count_subdomains_by_date.filter(date=date)
                _vuln = count_vulns_by_date.filter(date=date)
                _scan = count_scans_by_date.filter(date=date)
                _endpoint = count_endpoints_by_date.filter(date=date)
                if _target:
                    targets_in_last_week.append(_target[0]["created_count"])
                else:
                    targets_in_last_week.append(0)
                if _subdomain:
                    subdomains_in_last_week.append(_subdomain[0]["count"])
                else:
                    subdomains_in_last_week.append(0)
                if _vuln:
                    vulns_in_last_week.append(_vuln[0]["count"])
                else:
                    vulns_in_last_week.append(0)
                if _scan:
                    scans_in_last_week.append(_scan[0]["count"])
                else:
                    scans_in_last_week.append(0)
                if _endpoint:
                    endpoints_in_last_week.append(_endpoint[0]["count"])
                else:
                    endpoints_in_last_week.append(0)

            targets_in_last_week.reverse()
            subdomains_in_last_week.reverse()
            vulns_in_last_week.reverse()
            scans_in_last_week.reverse()
            endpoints_in_last_week.reverse()

            context = {
                "dashboard_data_active": "active",
                "domain_count": domain_count,
                "endpoint_count": endpoint_count,
                "scan_count": scan_count,
                "subdomain_count": subdomain_count,
                "subdomain_with_ip_count": subdomain_with_ip_count,
                "alive_count": alive_count,
                "endpoint_alive_count": endpoint_alive_count,
                "info_count": info_count,
                "low_count": low_count,
                "medium_count": medium_count,
                "high_count": high_count,
                "critical_count": critical_count,
                "unknown_count": unknown_count,
                "most_common_vulnerability": most_common_vulnerability,
                "total_vul_count": total_vul_count,
                "total_vul_ignore_info_count": total_vul_ignore_info_count,
                "vulnerability_feed": vulnerability_feed,
                "activity_feed": activity_feed,
                "targets_in_last_week": targets_in_last_week,
                "subdomains_in_last_week": subdomains_in_last_week,
                "vulns_in_last_week": vulns_in_last_week,
                "scans_in_last_week": scans_in_last_week,
                "endpoints_in_last_week": endpoints_in_last_week,
                "last_7_dates": last_7_dates,
                "vul_ports": vul_ports,
                "latest_vulnerabilities": latest_vulnerabilities,
                "sd_analysis": sd_analysis,
                "ip_analysis": ip_analysis,
                "vul_analysis": vul_analysis,
                "port_analysis": port_analysis,
            }

            context["total_ips"] = org_ip.count()
            context["most_used_port"] = (
                Port.objects.filter(ports__pk__in=org_ip_id)
                .annotate(count=Count("ports"))
                .order_by("-count")
                .values()[:7]
            )
            context["most_used_ip"] = (
                org_ip.annotate(count=Count("ip_addresses"))
                .order_by("-count")
                .exclude(ip_addresses__isnull=True)
                .values()[:7]
            )
            context["most_used_tech"] = (
                Technology.objects.filter(technologies__pk__in=org_subdomain_id)
                .annotate(count=Count("technologies"))
                .order_by("-count")
                .values()[:7]
            )

            context["most_common_cve"] = (
                CveId.objects.filter(cve_ids__pk__in=vulnerabilities_id)
                .annotate(nused=Count("cve_ids"))
                .order_by("-nused")
                .values("name", "nused")[:7]
            )
            context["most_common_cwe"] = (
                CweId.objects.filter(cwe_ids__pk__in=vulnerabilities_id)
                .annotate(nused=Count("cwe_ids"))
                .order_by("-nused")
                .values("name", "nused")[:7]
            )
            context["most_common_tags"] = (
                VulnerabilityTags.objects.filter(vuln_tags__pk__in=vulnerabilities_id)
                .annotate(nused=Count("vuln_tags"))
                .order_by("-nused")
                .values("name", "nused")[:7]
            )

            context["asset_countries"] = (
                CountryISO.objects.filter(id__in=ctr_iso_id)
                .annotate(count=Count("ipaddress"))
                .order_by("-count")
                .values()
            )
            print(context, "ds")

            return Response(context)
        except Exception as e:
            print(e)
            return Response({"desc": str(e)})


class OrgScanStatus(APIView):
    def post(self, request):
        # main tasks
        req = self.request
        data = req.data
        orgId = data["org_id"]
        print(orgId)
        response = {"status": False}
        org_domain = list(
            Organization.objects.get(id=orgId)
            .get_domains()
            .values_list("id", flat=True)
        )
        #     response = {"status": True}
        #     print(list(org_domain), "gotIt")
        try:
            recently_completed_scans_all = (
                ScanHistory.objects.all()
                .order_by("-start_scan_date")
                .filter(Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3))
                .filter(domain_id__in=org_domain)
            )
            recently_completed_scans = recently_completed_scans_all[:10]
            currently_scanning = (
                ScanHistory.objects.order_by("-start_scan_date")
                .filter(scan_status=1)
                .filter(domain_id__in=org_domain)
            )
            pending_scans = ScanHistory.objects.filter(scan_status=-1).filter(
                domain_id__in=org_domain
            )

            # subtasks
            recently_completed_tasks = (
                SubScan.objects.all()
                .order_by("-start_scan_date")
                .filter(Q(status=0) | Q(status=2) | Q(status=3))
                .filter(
                    scan_history_id__in=list(
                        recently_completed_scans_all.values_list("id", flat=True)
                    )
                )[:15]
            )
            currently_running_tasks = (
                SubScan.objects.order_by("-start_scan_date")
                .filter(status=1)
                .filter(
                    scan_history_id__in=list(
                        currently_scanning.values_list("id", flat=True)
                    )
                )
            )
            pending_tasks = SubScan.objects.filter(status=-1).filter(
                scan_history_id__in=list(pending_scans.values_list("id", flat=True))
            )

            response = {
                "scans": {
                    "pending": ScanHistorySerializer(pending_scans, many=True).data,
                    "scanning": ScanHistorySerializer(
                        currently_scanning, many=True
                    ).data,
                    "completed": ScanHistorySerializer(
                        recently_completed_scans, many=True
                    ).data,
                },
                "tasks": {
                    "pending": SubScanSerializer(pending_tasks, many=True).data,
                    "running": SubScanSerializer(
                        currently_running_tasks, many=True
                    ).data,
                    "completed": SubScanSerializer(
                        recently_completed_tasks, many=True
                    ).data,
                },
            }
        except Exception as e:
            print(e)
            response = {"status": False}
        return Response(response)


class ScheduleStartScan(APIView):
    def post(self, request):
        # schedule single domain and org scan
        # start multile domain scan
        req = self.request
        data = req.data
        list_of_domains = data.get("listOfDomainId")
        host_id = data.get("domainId")
        is_schedule = data.get("schedule")
        org_id = data.get("orgId")
        # for subdomain in data["importSubdomainTextArea"].split("\n")
        # for subdomain in request.POST["outOfScopeSubdomainTextarea"].split(",")
        import_subdomain = data.get("importSubdomainTextArea")
        out_of_scope_subdomain = data.get("outOfScopeSubdomainTextarea")
        engine_type = data["scanMode"]
        scheduled_mode = data.get("scheduledMode")
        print(
            list_of_domains,
            host_id,
            is_schedule,
            org_id,
            import_subdomain,
            out_of_scope_subdomain,
            engine_type,
            scheduled_mode,
            "rock",
        )
        # if request.method == "POST":
        # get imported subdomains
        if import_subdomain:
            imported_subdomains = [
                subdomain.rstrip() for subdomain in import_subdomain.split(",")
            ]
        else:
            imported_subdomains = []
        if imported_subdomains:
            imported_subdomains = [
                subdomain for subdomain in imported_subdomains if subdomain
            ]
        else:
            imported_subdomains = []
        if out_of_scope_subdomain:
            out_of_scope_subdomains = [
                subdomain.rstrip() for subdomain in out_of_scope_subdomain.split(",")
            ]
        else:
            out_of_scope_subdomains = []
        if out_of_scope_subdomains:
            out_of_scope_subdomains = [
                subdomain for subdomain in out_of_scope_subdomains if subdomain
            ]
        else:
            out_of_scope_subdomains = []
        # get engine type
        # engine_type = int(request.POST["scan_mode"])
        engine_object = get_object_or_404(EngineType, id=engine_type)
        if is_schedule == True:
            if host_id:
                domain = Domain.objects.get(id=host_id)
                task_name = (
                    engine_object.engine_name
                    + " for "
                    + domain.name
                    + ":"
                    + str(
                        datetime.datetime.strftime(timezone.now(), "%Y_%m_%d_%H_%M_%S")
                    )
                )
                if scheduled_mode == "periodic":
                    # periodic task
                    frequency_value = int(data["frequency"])
                    frequency_type = data["frequency_type"]
                    if frequency_type == "minutes":
                        period = IntervalSchedule.MINUTES
                    elif frequency_type == "hours":
                        period = IntervalSchedule.HOURS
                    elif frequency_type == "days":
                        period = IntervalSchedule.DAYS
                    elif frequency_type == "weeks":
                        period = IntervalSchedule.DAYS
                        frequency_value *= 7
                    elif frequency_type == "months":
                        period = IntervalSchedule.DAYS
                        frequency_value *= 30

                    schedule, created = IntervalSchedule.objects.get_or_create(
                        every=frequency_value,
                        period=period,
                    )
                    _kwargs = json.dumps(
                        {
                            "domain_id": host_id,
                            "scan_history_id": 0,
                            "scan_type": 1,
                            "engine_type": engine_type,
                            "imported_subdomains": imported_subdomains,
                        }
                    )
                    PeriodicTask.objects.create(
                        interval=schedule,
                        name=task_name,
                        task="reNgine.tasks.initiate_scan",
                        kwargs=_kwargs,
                    )
                elif scheduled_mode == "clocked":
                    # clocked task
                    schedule_time = data["scheduled_time"]
                    print(schedule_time, "clll")
                    clock, created = ClockedSchedule.objects.get_or_create(
                        clocked_time=schedule_time,
                    )
                    _kwargs = json.dumps(
                        {
                            "domain_id": host_id,
                            "scan_history_id": 0,
                            "scan_type": 1,
                            "engine_type": engine_type,
                            "imported_subdomains": imported_subdomains,
                        }
                    )
                    PeriodicTask.objects.create(
                        clocked=clock,
                        one_off=True,
                        name=task_name,
                        task="reNgine.tasks.initiate_scan",
                        kwargs=_kwargs,
                    )

                return Response({"status": True})
            if org_id:
                organization = Organization.objects.get(id=org_id)
                for domain in organization.get_domains():
                    task_name = (
                        engine_object.engine_name
                        + " for "
                        + domain.name
                        + ":"
                        + str(
                            datetime.datetime.strftime(
                                timezone.now(), "%Y_%m_%d_%H_%M_%S"
                            )
                        )
                    )
                    if scheduled_mode == "periodic":
                        # periodic task
                        frequency_value = int(data["frequency"])
                        frequency_type = data["frequency_type"]
                        if frequency_type == "minutes":
                            period = IntervalSchedule.MINUTES
                        elif frequency_type == "hours":
                            period = IntervalSchedule.HOURS
                        elif frequency_type == "days":
                            period = IntervalSchedule.DAYS
                        elif frequency_type == "weeks":
                            period = IntervalSchedule.DAYS
                            frequency_value *= 7
                        elif frequency_type == "months":
                            period = IntervalSchedule.DAYS
                            frequency_value *= 30

                        schedule, created = IntervalSchedule.objects.get_or_create(
                            every=frequency_value,
                            period=period,
                        )
                        _kwargs = json.dumps(
                            {
                                "domain_id": domain.id,
                                "scan_history_id": 0,
                                "scan_type": 1,
                                "engine_type": engine_type,
                                "imported_subdomains": None,
                            }
                        )
                        PeriodicTask.objects.create(
                            interval=schedule,
                            name=task_name,
                            task="reNgine.tasks.initiate_scan",
                            kwargs=_kwargs,
                        )
                    elif scheduled_mode == "clocked":
                        # clocked task
                        schedule_time = data["scheduled_time"]
                        clock, created = ClockedSchedule.objects.get_or_create(
                            clocked_time=schedule_time,
                        )
                        _kwargs = json.dumps(
                            {
                                "domain_id": domain.id,
                                "scan_history_id": 0,
                                "scan_type": 1,
                                "engine_type": engine_type,
                                "imported_subdomains": None,
                            }
                        )
                        PeriodicTask.objects.create(
                            clocked=clock,
                            one_off=True,
                            name=task_name,
                            task="reNgine.tasks.initiate_scan",
                            kwargs=_kwargs,
                        )
                return Response({"status": True})
        else:
            print("ok")

            if list_of_domains:
                print("ya")

                for domain_id in list_of_domains:
                    # start the celery task
                    scan_history_id = create_scan_object(domain_id, engine_type)
                    celery_task = initiate_scan.apply_async(
                        args=(domain_id, scan_history_id, 0, engine_type)
                    )
                    ScanHistory.objects.filter(id=scan_history_id).update(
                        celery_id=celery_task.id
                    )
                print("true")
                return Response({"status": True})
        return Response({"status": False})


class QueryInterestingSubdomains(APIView):
    def get(self, request):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")

        if scan_id:
            queryset = get_interesting_subdomains(scan_history=scan_id)
        elif target_id:
            queryset = get_interesting_subdomains(target=target_id)
        else:
            queryset = get_interesting_subdomains()

        queryset = queryset.distinct("name")

        return Response(InterestingSubdomainSerializer(queryset, many=True).data)


@login_not_required
class ListTargetsDatatableViewSet(viewsets.ModelViewSet):
    queryset = Domain.objects.all()
    serializer_class = DomainSerializer

    def get_queryset(self):
        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        print("filtered", int(self.request.GET.get("orgId", 0)))
        orgId = int(self.request.GET.get("orgId", 0))
        if orgId:
            org_domain = list(
                Organization.objects.get(id=orgId)
                .get_domains()
                .values_list("id", flat=True)
            )
            print(org_domain, "1")
            qs = qs.filter(id__in=org_domain)
            print("2", qs)

        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        if search_value or _order_col or _order_direction:
            order_col = "id"
            if _order_col == "2":
                order_col = "name"
            elif _order_col == "4":
                order_col = "insert_date"
            elif _order_col == "5":
                order_col = "start_scan_date"
                if _order_direction == "desc":
                    return qs.order_by(F("start_scan_date").desc(nulls_last=True))
                return qs.order_by(F("start_scan_date").asc(nulls_last=True))

            if _order_direction == "desc":
                order_col = "-{}".format(order_col)

            qs = self.queryset.filter(
                Q(name__icontains=search_value)
                | Q(description__icontains=search_value)
                | Q(domains__name__icontains=search_value)
            )
            return qs.order_by(order_col)

        return qs.order_by("-id")


class WafDetector(APIView):
    def get(self, request):
        req = self.request
        url = req.query_params.get("url")
        response = {}
        response["status"] = False

        wafw00f_command = "wafw00f {}".format(url)
        output = subprocess.check_output(wafw00f_command, shell=True)
        # use regex to get the waf
        regex = "behind \\\\x1b\[1;96m(.*)\\\\x1b"
        group = re.search(regex, str(output))

        if group:
            response["status"] = True
            response["results"] = group.group(1)
        else:
            response["message"] = "Could not detect any WAF!"

        return Response(response)


class SearchHistoryView(APIView):
    def get(self, request):
        req = self.request

        response = {}
        response["status"] = False

        scan_history = SearchHistory.objects.all().order_by("-id")[:5]

        if scan_history:
            response["status"] = True
            response["results"] = SearchHistorySerializer(scan_history, many=True).data

        return Response(response)


class UniversalSearch(APIView):
    def get(self, request):
        req = self.request
        query = req.query_params.get("query")

        response = {}
        response["status"] = False

        if not query:
            response["message"] = "No query parameter provided!"
            return Response(response)

        response["results"] = {}

        # search history to be saved
        SearchHistory.objects.get_or_create(query=query)

        # lookup query in subdomain
        subdomain = Subdomain.objects.filter(
            Q(name__icontains=query)
            | Q(cname__icontains=query)
            | Q(page_title__icontains=query)
            | Q(http_url__icontains=query)
        ).distinct("name")
        subdomain_data = SubdomainSerializer(subdomain, many=True).data
        response["results"]["subdomains"] = subdomain_data

        endpoint = EndPoint.objects.filter(
            Q(http_url__icontains=query) | Q(page_title__icontains=query)
        ).distinct("http_url")
        endpoint_data = EndpointSerializer(endpoint, many=True).data
        response["results"]["endpoints"] = endpoint_data

        vulnerability = Vulnerability.objects.filter(
            Q(http_url__icontains=query)
            | Q(name__icontains=query)
            | Q(description__icontains=query)
        ).distinct()
        vulnerability_data = VulnerabilitySerializer(vulnerability, many=True).data
        response["results"]["vulnerabilities"] = vulnerability_data

        response["results"]["others"] = {}

        if subdomain_data or endpoint_data or vulnerability_data:
            response["status"] = True

        return Response(response)


class FetchMostCommonVulnerability(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        limit = data.get("limit", 20)
        scan_history_id = data.get("scan_history_id")
        target_id = data.get("target_id")
        is_ignore_info = data.get("ignore_info", False)

        response = {}
        response["status"] = False

        if scan_history_id:
            if is_ignore_info:
                most_common_vulnerabilities = (
                    Vulnerability.objects.filter(scan_history__id=scan_history_id)
                    .values("name", "severity")
                    .exclude(severity=0)
                    .annotate(count=Count("name"))
                    .order_by("-count")[:limit]
                )
            else:
                most_common_vulnerabilities = (
                    Vulnerability.objects.filter(scan_history__id=scan_history_id)
                    .values("name", "severity")
                    .annotate(count=Count("name"))
                    .order_by("-count")[:limit]
                )

        elif target_id:
            if is_ignore_info:
                most_common_vulnerabilities = (
                    Vulnerability.objects.filter(target_domain__id=target_id)
                    .values("name", "severity")
                    .exclude(severity=0)
                    .annotate(count=Count("name"))
                    .order_by("-count")[:limit]
                )
            else:
                most_common_vulnerabilities = (
                    Vulnerability.objects.filter(target_domain__id=target_id)
                    .values("name", "severity")
                    .annotate(count=Count("name"))
                    .order_by("-count")[:limit]
                )

        else:
            if is_ignore_info:
                most_common_vulnerabilities = (
                    Vulnerability.objects.values("name", "severity")
                    .exclude(severity=0)
                    .annotate(count=Count("name"))
                    .order_by("-count")[:limit]
                )
            else:
                most_common_vulnerabilities = (
                    Vulnerability.objects.values("name", "severity")
                    .annotate(count=Count("name"))
                    .order_by("-count")[:limit]
                )

        most_common_vulnerabilities = [vuln for vuln in most_common_vulnerabilities]

        if most_common_vulnerabilities:
            response["status"] = True
            response["result"] = most_common_vulnerabilities

        return Response(response)


class FetchMostVulnerable(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        scan_history_id = data.get("scan_history_id")
        target_id = data.get("target_id")
        limit = data.get("limit", 20)
        is_ignore_info = data.get("ignore_info", False)

        response = {}
        response["status"] = False

        if scan_history_id:
            if is_ignore_info:
                most_vulnerable_subdomains = (
                    Subdomain.objects.filter(scan_history__id=scan_history_id)
                    .annotate(
                        vuln_count=Count(
                            "vulnerability__name", filter=~Q(vulnerability__severity=0)
                        )
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )
            else:
                most_vulnerable_subdomains = (
                    Subdomain.objects.filter(scan_history__id=scan_history_id)
                    .annotate(vuln_count=Count("vulnerability__name"))
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )

            if most_vulnerable_subdomains:
                response["status"] = True
                response["result"] = SubdomainSerializer(
                    most_vulnerable_subdomains, many=True
                ).data

        elif target_id:
            if is_ignore_info:
                most_vulnerable_subdomains = (
                    Subdomain.objects.filter(target_domain__id=target_id)
                    .annotate(
                        vuln_count=Count(
                            "vulnerability__name", filter=~Q(vulnerability__severity=0)
                        )
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )
            else:
                most_vulnerable_subdomains = (
                    Subdomain.objects.filter(target_domain__id=target_id)
                    .annotate(vuln_count=Count("vulnerability__name"))
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )

            if most_vulnerable_subdomains:
                response["status"] = True
                response["result"] = SubdomainSerializer(
                    most_vulnerable_subdomains, many=True
                ).data
        else:
            if is_ignore_info:
                most_vulnerable_targets = (
                    Domain.objects.annotate(
                        vuln_count=Count(
                            "subdomain__vulnerability__name",
                            filter=~Q(subdomain__vulnerability__severity=0),
                        )
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )
            else:
                most_vulnerable_targets = (
                    Domain.objects.annotate(
                        vuln_count=Count("subdomain__vulnerability__name")
                    )
                    .order_by("-vuln_count")
                    .exclude(vuln_count=0)[:limit]
                )

            if most_vulnerable_targets:
                response["status"] = True
                response["result"] = DomainSerializer(
                    most_vulnerable_targets, many=True
                ).data

        return Response(response)


class CVEDetails(APIView):
    def get(self, request):
        req = self.request

        cve_id = req.query_params.get("cve_id")

        if not cve_id:
            return Response({"status": False, "message": "CVE ID not provided"})

        response = requests.get("https://cve.circl.lu/api/cve/" + cve_id)

        if response.status_code != 200:
            return Response({"status": False, "message": "Unknown Error Occured!"})

        if not response.json():
            return Response({"status": False, "message": "CVE ID does not exists."})

        return Response({"status": True, "result": response.json()})


class AddReconNote(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        subdomain_id = data.get("subdomain_id")
        scan_history_id = data.get("scan_history_id")
        title = data.get("title")
        description = data.get("description")

        try:
            note = TodoNote()
            note.title = title
            note.description = description

            if scan_history_id:
                scan_history = ScanHistory.objects.get(id=scan_history_id)
                note.scan_history = scan_history

            # get scan history for subdomain_id
            if subdomain_id:
                subdomain = Subdomain.objects.get(id=subdomain_id)
                note.subdomain = subdomain

                # also get scan history
                scan_history_id = subdomain.scan_history.id
                scan_history = ScanHistory.objects.get(id=scan_history_id)
                note.scan_history = scan_history

            note.save()
            response = {"status": True}
        except Exception as e:
            response = {"status": False, "message": str(e)}

        return Response(response)


class ToggleSubdomainImportantStatus(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        subdomain_id = data.get("subdomain_id")

        response = {"status": False, "message": "No subdomain_id provided"}

        name = Subdomain.objects.get(id=subdomain_id)
        name.is_important = not name.is_important
        name.save()

        response = {"status": True}

        return Response(response)


# class AddTarget(APIView):
#     def post(self, request):
#         req = self.request
#         data = req.data

#         target_name = data.get("domain_name")
#         h1_team_handle = data.get("h1_team_handle")
#         description = data.get("description")
#         ip_address = data.get("ip_address")

#         try:
#             if not target_name:
#                 return Response({"status": False, "message": "domain_name missing!"})

#             # validate if target_name is a valid domain_name
#             if not validators.domain(target_name):
#                 return Response({"status": False, "message": "Invalid Domain or IP"})

#             org_instance = Organization.objects.get(id=data["org_id"])
#             print(org_instance, "oiiins")
#             if Domain.objects.filter(name=target_name).exists():
#                 domain = Domain.objects.get(name=target_name)
#                 if ip_address:
#                     domain.ip_address_cidr = ip_address
#                 domain.save()
#                 org_instance.domains.add(domain)
#                 return Response(
#                     {
#                         "status": False,
#                         "message": "Target already exists!",
#                         "domain_id": domain.id,
#                     }
#                 )

#             domain = Domain()
#             domain.description = description
#             domain.name = target_name
#             domain.insert_date = timezone.now()
#             domain.h1_team_handle = h1_team_handle

#             if ip_address:
#                 domain.ip_address_cidr = ip_address
#             domain.save()
#             org_instance.domains.add(domain)

#             return Response(
#                 {
#                     "status": True,
#                     "message": "Domain successfully added as target!",
#                     "domain_name": target_name,
#                     "domain_id": domain.id,
#                 }
#             )
#         except Exception as e:
#             return Response({"status": False, "desc": str(e)})


class FetchSubscanResults(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        subscan_id = data["subscan_id"]

        if not SubScan.objects.filter(id=subscan_id).exists():
            return Response(
                {
                    "status": False,
                    "error": "Subscan {} does not exist".format(subscan_id),
                }
            )

        subscan = SubScan.objects.filter(id=subscan_id)
        subscan_data = SubScanResultSerializer(subscan[0], many=False).data

        subscan_results = None

        if subscan[0].port_scan:
            ips_in_subscan = IpAddress.objects.filter(ip_subscan_ids__in=subscan)
            subscan_results = IpSerializer(ips_in_subscan, many=True).data

        elif subscan[0].vulnerability_scan:
            vulns_in_subscan = Vulnerability.objects.filter(
                vuln_subscan_ids__in=subscan
            )
            subscan_results = VulnerabilitySerializer(vulns_in_subscan, many=True).data

        elif subscan[0].fetch_url:
            endpoints_in_subscan = EndPoint.objects.filter(
                endpoint_subscan_ids__in=subscan
            )
            subscan_results = EndpointSerializer(endpoints_in_subscan, many=True).data

        elif subscan[0].dir_file_fuzz:
            dirs_in_subscan = DirectoryScan.objects.filter(dir_subscan_ids__in=subscan)
            subscan_results = DirectoryScanSerializer(dirs_in_subscan, many=True).data

        return Response({"subscan": subscan_data, "result": subscan_results})


class ListSubScans(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        subdomain_id = data.get("subdomain_id", None)

        scan_history = data.get("scan_history_id", None)

        domain_id = data.get("domain_id", None)

        response = {}

        response["status"] = False

        if subdomain_id:
            subscans = SubScan.objects.filter(subdomain__id=subdomain_id).order_by(
                "-stop_scan_date"
            )
            subscan_results = SubScanSerializer(subscans, many=True).data

            if subscans:
                response["status"] = True
                response["results"] = subscan_results

        elif scan_history:
            subscans = SubScan.objects.filter(scan_history__id=scan_history).order_by(
                "-stop_scan_date"
            )
            subscan_results = SubScanSerializer(subscans, many=True).data

            if subscans:
                response["status"] = True
                response["results"] = subscan_results

        elif domain_id:
            subscans = SubScan.objects.filter(
                scan_history__in=ScanHistory.objects.filter(domain__id=domain_id)
            ).order_by("-stop_scan_date")
            subscan_results = SubScanSerializer(subscans, many=True).data

            if subscans:
                response["status"] = True
                response["results"] = subscan_results

        return Response(response)


class DeleteMultipleRows(APIView):
    def post(self, request):
        req = self.request
        data = req.data

        try:
            if data["type"] == "subscan":
                for row in data["rows"]:
                    SubScan.objects.get(id=row).delete()
            response = True
        except Exception as e:
            response = False

        return Response({"status": response})


class StopScan(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        scan_id = data.get("scan_id")
        subscan_id = data.get("subscan_id")
        response = {}
        if scan_id:
            try:
                scan_history = get_object_or_404(ScanHistory, id=scan_id)
                app.control.revoke(
                    scan_history.celery_id, terminate=True, signal="SIGKILL"
                )
                scan_history.scan_status = 3
                scan_history.stop_scan_date = timezone.now()
                scan_history.save()

                if ScanActivity.objects.filter(scan_of=scan_history).exists():
                    last_activity = ScanActivity.objects.filter(
                        scan_of=scan_history
                    ).order_by("-pk")[0]
                    last_activity.status = 0
                    last_activity.time = timezone.now()
                    last_activity.save()
                create_scan_activity(scan_history, "Scan aborted", 0)
                response["status"] = True
            except Exception as e:
                logging.error(e)
                response = {"status": False, "message": str(e)}
        elif subscan_id:
            try:
                task = get_object_or_404(SubScan, id=subscan_id)
                app.control.revoke(task.celery_id, terminate=True, signal="SIGKILL")
                task.status = 3
                task.stop_scan_date = timezone.now()
                task.save()
                response["status"] = True
            except Exception as e:
                logging.error(e)
                response = {"status": False, "message": str(e)}
        return Response(response)


class InitiateSubTask(APIView):
    def post(self, request):
        req = self.request
        data = req.data
        engine_id = data.get("engine_id")
        for subdomain_id in data["subdomain_ids"]:
            # initiate subtask for every task types
            if data["port_scan"]:
                celery_task = initiate_subtask.apply_async(
                    args=(subdomain_id, True, False, False, False, False, engine_id)
                )

            if data["osint"]:
                celery_task = initiate_subtask.apply_async(
                    args=(subdomain_id, False, True, False, False, False, engine_id)
                )

            if data["endpoint"]:
                celery_task = initiate_subtask.apply_async(
                    args=(subdomain_id, False, False, True, False, False, engine_id)
                )

            if data["dir_fuzz"]:
                celery_task = initiate_subtask.apply_async(
                    args=(subdomain_id, False, False, False, True, False, engine_id)
                )

            if data["vuln_scan"]:
                celery_task = initiate_subtask.apply_async(
                    args=(subdomain_id, False, False, False, False, True, engine_id)
                )
        return Response({"status": True})


class DeleteSubdomain(APIView):
    def post(self, request):
        req = self.request
        for id in req.data["subdomain_ids"]:
            Subdomain.objects.get(id=id).delete()
        return Response({"status": True})


class ListInterestingKeywords(APIView):
    def get(self, request, format=None):
        req = self.request
        keywords = get_lookup_keywords()
        return Response(keywords)


class RengineUpdateCheck(APIView):
    def get(self, request):
        req = self.request
        github_api = "https://api.github.com/repos/yogeshojha/rengine/releases"
        response = requests.get(github_api).json()
        if "message" in response:
            return Response({"status": False, "message": "RateLimited"})

        return_response = {}

        # get current version_number
        # remove quotes from current_version
        current_version = (
            (os.environ["RENGINE_CURRENT_VERSION"])[1:]
            if os.environ["RENGINE_CURRENT_VERSION"][0] == "v"
            else os.environ["RENGINE_CURRENT_VERSION"]
        ).replace("'", "")

        # for consistency remove v from both if exists
        latest_version = re.search(
            r"v(\d+\.)?(\d+\.)?(\*|\d+)",
            (
                (response[0]["name"])[1:]
                if response[0]["name"][0] == "v"
                else response[0]["name"]
            ),
        )

        latest_version = latest_version.group(0) if latest_version else None

        if not latest_version:
            latest_version = re.search(
                r"(\d+\.)?(\d+\.)?(\*|\d+)",
                (
                    (response[0]["name"])[1:]
                    if response[0]["name"][0] == "v"
                    else response[0]["name"]
                ),
            )
            if latest_version:
                latest_version = latest_version.group(0)

        return_response["status"] = True
        return_response["latest_version"] = latest_version
        return_response["current_version"] = current_version
        return_response["update_available"] = version.parse(
            current_version
        ) < version.parse(latest_version)
        if version.parse(current_version) < version.parse(latest_version):
            return_response["changelog"] = response[0]["body"]

        return Response(return_response)


class UninstallTool(APIView):
    def get(self, request):
        req = self.request
        tool_id = req.query_params.get("tool_id")
        tool_name = req.query_params.get("name")

        if tool_id:
            tool = InstalledExternalTool.objects.get(id=tool_id)
        elif tool_name:
            tool = InstalledExternalTool.objects.get(name=tool_name)

        if tool.is_default:
            return Response(
                {"status": False, "message": "Default tools can not be uninstalled"}
            )

        # check install instructions, if it is installed using go, then remove from go bin path,
        # else try to remove from github clone path

        # getting tool name is tricky!

        if "go install" in tool.install_command:
            tool_name = tool.install_command.split("/")[-1].split("@")[0]
            uninstall_command = "rm /go/bin/" + tool_name
        elif "git clone" in tool.install_command:
            tool_name = (
                tool.install_command[:-1]
                if tool.install_command[-1] == "/"
                else tool.install_command
            )
            tool_name = tool_name.split("/")[-1]
            uninstall_command = "rm -rf " + tool.github_clone_path
        else:
            return Response({"status": False, "message": "Cannot uninstall tool!"})

        os.system(uninstall_command)
        run_system_commands.apply_async(args=(uninstall_command,))

        tool.delete()

        return Response({"status": True, "message": "Uninstall Tool Success"})


class UpdateTool(APIView):
    def get(self, request):
        req = self.request
        tool_id = req.query_params.get("tool_id")
        tool_name = req.query_params.get("name")

        if tool_id:
            tool = InstalledExternalTool.objects.get(id=tool_id)
        elif tool_name:
            tool = InstalledExternalTool.objects.get(name=tool_name)

        # if git clone was used for installation, then we must use git pull inside project directory,
        # otherwise use the same command as given

        update_command = tool.update_command.lower()

        if not update_command:
            return Response(
                {
                    "status": False,
                    "message": tool.name
                    + "has missing update command! Cannot update the tool.",
                }
            )
        elif update_command == "git pull":
            tool_name = (
                tool.install_command[:-1]
                if tool.install_command[-1] == "/"
                else tool.install_command
            )
            tool_name = tool_name.split("/")[-1]
            update_command = "cd /usr/src/github/" + tool_name + " && git pull && cd -"

        os.system(update_command)
        run_system_commands.apply_async(args=(update_command,))
        return Response(
            {"status": True, "message": tool.name + " upated successfully."}
        )


class GetExternalToolCurrentVersion(APIView):
    def get(self, request):
        req = self.request
        # toolname is also the command
        tool_id = req.query_params.get("tool_id")
        tool_name = req.query_params.get("name")
        # can supply either tool id or tool_name

        tool = None

        if tool_id:
            if not InstalledExternalTool.objects.filter(id=tool_id).exists():
                return Response({"status": False, "message": "Tool Not found"})
            tool = InstalledExternalTool.objects.get(id=tool_id)
        elif tool_name:
            if not InstalledExternalTool.objects.filter(name=tool_name).exists():
                return Response({"status": False, "message": "Tool Not found"})
            tool = InstalledExternalTool.objects.get(name=tool_name)

        if not tool.version_lookup_command:
            return Response(
                {"status": False, "message": "Version Lookup command not provided."}
            )

        p = subprocess.Popen(
            tool.version_lookup_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        version_number = None
        for line in p.stdout.readlines():
            version_number = re.search(re.compile(tool.version_match_regex), str(line))
            if version_number:
                break

        if not version_number:
            return Response(
                {"status": False, "message": "Invalid version lookup command."}
            )

        return Response(
            {
                "status": True,
                "version_number": version_number.group(0),
                "tool_name": tool.name,
            }
        )


class GithubToolCheckGetLatestRelease(APIView):
    def get(self, request):
        req = self.request

        tool_id = req.query_params.get("tool_id")
        tool_name = req.query_params.get("name")

        if not InstalledExternalTool.objects.filter(id=tool_id).exists():
            return Response({"status": False, "message": "Tool Not found"})

        if tool_id:
            tool = InstalledExternalTool.objects.get(id=tool_id)
        elif tool_name:
            tool = InstalledExternalTool.objects.get(name=tool_name)

        if not tool.github_url:
            return Response(
                {
                    "status": False,
                    "message": "Github URL is not provided, Cannot check updates",
                }
            )

        # if tool_github_url has https://github.com/ remove and also remove trailing /
        tool_github_url = tool.github_url.replace("http://github.com/", "").replace(
            "https://github.com/", ""
        )
        tool_github_url = remove_lead_and_trail_slash(tool_github_url)
        github_api = "https://api.github.com/repos/{}/releases".format(tool_github_url)
        response = requests.get(github_api).json()
        # check if api rate limit exceeded
        if "message" in response and response["message"] == "RateLimited":
            return Response({"status": False, "message": "RateLimited"})
        elif "message" in response and response["message"] == "Not Found":
            return Response({"status": False, "message": "Not Found"})
        # only send latest release
        response = response[0]

        api_response = {
            "status": True,
            "url": response["url"],
            "id": response["id"],
            "name": response["name"],
            "changelog": response["body"],
        }
        return Response(api_response)


class ScanStatus(APIView):
    def get(self, request):
        # main tasks
        recently_completed_scans = (
            ScanHistory.objects.all()
            .order_by("-start_scan_date")
            .filter(Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3))[:10]
        )
        currently_scanning = ScanHistory.objects.order_by("-start_scan_date").filter(
            scan_status=1
        )
        pending_scans = ScanHistory.objects.filter(scan_status=-1)

        # subtasks
        recently_completed_tasks = (
            SubScan.objects.all()
            .order_by("-start_scan_date")
            .filter(Q(status=0) | Q(status=2) | Q(status=3))[:15]
        )
        currently_running_tasks = SubScan.objects.order_by("-start_scan_date").filter(
            status=1
        )
        pending_tasks = SubScan.objects.filter(status=-1)

        response = {
            "scans": {
                "pending": ScanHistorySerializer(pending_scans, many=True).data,
                "scanning": ScanHistorySerializer(currently_scanning, many=True).data,
                "completed": ScanHistorySerializer(
                    recently_completed_scans, many=True
                ).data,
            },
            "tasks": {
                "pending": SubScanSerializer(pending_tasks, many=True).data,
                "running": SubScanSerializer(currently_running_tasks, many=True).data,
                "completed": SubScanSerializer(
                    recently_completed_tasks, many=True
                ).data,
            },
        }
        return Response(response)


class Whois(APIView):
    def get(self, request):
        req = self.request
        ip_domain = req.query_params.get("ip_domain")
        if not validators.domain(ip_domain):
            return Response({"status": False, "message": "Invalid Domain or IP"})
        save_db = True if "save_db" in req.query_params else False
        # fetch_from_db query param can be used to pull the whois record directly from db
        # instead of fetching new
        # if fetch_from_db = True, will not be queried to domainbigdata
        fetch_from_db = True if "fetch_from_db" in req.query_params else False
        response = get_whois(ip_domain, save_db=save_db, fetch_from_db=fetch_from_db)
        if response:
            return Response(response)
        return Response({"status": False})


class CMSDetector(APIView):
    def get(self, request):
        req = self.request
        url = req.query_params.get("url")
        # save_db = True if 'save_db' in req.query_params else False
        response = {"status": False}
        try:
            response = get_cms_details(url)
        except Exception as e:
            response = {"status": False, "message": str(e)}
        return Response(response)


import socket


class IPToDomain(APIView):
    def get(self, request):
        req = self.request
        print(req.query_params, "q")
        ip_address = req.query_params.get("ip_address")
        if not ip_address:
            return Response({"status": False, "message": "IP Address Required"})
        try:
            logging.info(f"Resolving IP address {ip_address} ...")
            domain, domains, ips = socket.gethostbyaddr(ip_address)
            response = {
                "status": True,
                "ip_address": ip_address,
                "domains": domains or [domain],
                "resolves_to": domain,
            }
        except socket.herror:  # ip does not have a PTR record
            logging.info(f"No PTR record for {ip_address}")
            response = {
                "status": True,
                "ip_address": ip_address,
                "domains": [ip_address],
                "resolves_to": ip_address,
            }
        except Exception as e:
            logging.info(e)
            response = {
                "status": False,
                "ip_address": ip_address,
                "message": "Exception {}".format(e),
            }
        finally:
            return Response(response)


class VulnerabilityReport(APIView):
    def get(self, request):
        req = self.request
        vulnerability_id = req.query_params.get("vulnerability_id")
        return Response({"status": send_hackerone_report(vulnerability_id)})


class GetFileContents(APIView):
    def get(self, request, format=None):
        req = self.request
        name = req.query_params.get("name")

        response = {}
        response["status"] = False

        if "nuclei_config" in req.query_params:
            path = "/root/.config/nuclei/config.yaml"
            if not os.path.exists(path):
                os.system("touch {}".format(path))
                response["message"] = "File Created!"
            f = open(path, "r")
            response["status"] = True
            response["content"] = f.read()
            return Response(response)

        if "subfinder_config" in req.query_params:
            path = "/root/.config/subfinder/config.yaml"
            if not os.path.exists(path):
                os.system("touch {}".format(path))
                response["message"] = "File Created!"
            f = open(path, "r")
            response["status"] = True
            response["content"] = f.read()
            return Response(response)

        if "naabu_config" in req.query_params:
            path = "/root/.config/naabu/config.yaml"
            if not os.path.exists(path):
                os.system("touch {}".format(path))
                response["message"] = "File Created!"
            f = open(path, "r")
            response["status"] = True
            response["content"] = f.read()
            return Response(response)

        if "theharvester_config" in req.query_params:
            path = "/usr/src/github/theHarvester/api-keys.yaml"
            if not os.path.exists(path):
                os.system("touch {}".format(path))
                response["message"] = "File Created!"
            f = open(path, "r")
            response["status"] = True
            response["content"] = f.read()
            return Response(response)

        if "amass_config" in req.query_params:
            path = "/root/.config/amass.ini"
            if not os.path.exists(path):
                os.system("touch {}".format(path))
                response["message"] = "File Created!"
            f = open(path, "r")
            response["status"] = True
            response["content"] = f.read()
            return Response(response)

        if "gf_pattern" in req.query_params:
            basedir = "/root/.gf"
            path = "/root/.gf/{}.json".format(name)
            if is_safe_path(basedir, path) and os.path.exists(path):
                content = open(path, "r").read()
                response["status"] = True
                response["content"] = content
            else:
                response["message"] = "Invalid path!"
                response["status"] = False
            return Response(response)

        if "nuclei_template" in req.query_params:
            safe_dir = "/root/nuclei-templates"
            path = "/root/nuclei-templates/{}".format(name)
            if is_safe_path(safe_dir, path) and os.path.exists(path):
                content = open(path.format(name), "r").read()
                response["status"] = True
                response["content"] = content
            else:
                response["message"] = "Invalid Path!"
                response["status"] = False
            return Response(response)

        response["message"] = "Invalid Query Params"
        return Response(response)


class ListTodoNotes(APIView):
    def get(self, request, format=None):
        req = self.request
        notes = TodoNote.objects.all().order_by("-id")
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")
        todo_id = req.query_params.get("todo_id")
        subdomain_id = req.query_params.get("subdomain_id")
        if target_id:
            notes = notes.filter(
                scan_history__in=ScanHistory.objects.filter(domain__id=target_id)
            )
        elif scan_id:
            notes = notes.filter(scan_history__id=scan_id)
        if todo_id:
            notes = notes.filter(id=todo_id)
        if subdomain_id:
            notes = notes.filter(subdomain__id=subdomain_id)
        notes = ReconNoteSerializer(notes, many=True)
        return Response({"notes": notes.data})


class ListScanHistory(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_history = ScanHistory.objects.all().order_by("-start_scan_date")
        scan_history = ScanHistorySerializer(scan_history, many=True)
        return Response(scan_history.data)


class ListEngines(APIView):
    def get(self, request, format=None):
        req = self.request
        engine = EngineType.objects.all()
        engine_serializer = EngineSerializer(engine, many=True)
        return Response({"engines": engine_serializer.data})


class ListOrganizations(APIView):
    def get(self, request, format=None):
        req = self.request
        organizations = Organization.objects.all()
        organization_serializer = OrganizationSerializer(organizations, many=True)
        return Response({"organizations": organization_serializer.data})


class ListTargetsInOrganization(APIView):
    def get(self, request, format=None):
        req = self.request
        organization_id = req.query_params.get("organization_id")
        organization = Organization.objects.filter(id=organization_id)
        targets = Domain.objects.filter(domains__in=organization)
        organization_serializer = OrganizationSerializer(organization, many=True)
        targets_serializer = OrganizationTargetsSerializer(targets, many=True)
        return Response(
            {
                "organization": organization_serializer.data,
                "domains": targets_serializer.data,
            }
        )


class ListTargetsWithoutOrganization(APIView):
    def get(self, request, format=None):
        req = self.request
        targets = Domain.objects.exclude(domains__in=Organization.objects.all())
        targets_serializer = OrganizationTargetsSerializer(targets, many=True)
        return Response({"domains": targets_serializer.data})


class VisualiseData(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            mitch_data = ScanHistory.objects.filter(id=scan_id)
            serializer = VisualiseDataSerializer(mitch_data, many=True)
            return Response(serializer.data)
        else:
            return Response()


class ListTechnology(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")

        if target_id:
            tech = (
                Technology.objects.filter(
                    technologies__in=Subdomain.objects.filter(
                        target_domain__id=target_id
                    )
                )
                .annotate(count=Count("name"))
                .order_by("-count")
            )
            serializer = TechnologyCountSerializer(tech, many=True)
            return Response({"technologies": serializer.data})
        elif scan_id:
            tech = (
                Technology.objects.filter(
                    technologies__in=Subdomain.objects.filter(scan_history__id=scan_id)
                )
                .annotate(count=Count("name"))
                .order_by("-count")
            )
            serializer = TechnologyCountSerializer(tech, many=True)
            return Response({"technologies": serializer.data})
        else:
            tech = (
                Technology.objects.filter(technologies__in=Subdomain.objects.all())
                .annotate(count=Count("name"))
                .order_by("-count")
            )
            serializer = TechnologyCountSerializer(tech, many=True)
            return Response({"technologies": serializer.data})


class ListDorkTypes(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            dork = (
                Dork.objects.filter(dorks__in=ScanHistory.objects.filter(id=scan_id))
                .values("type")
                .annotate(count=Count("type"))
                .order_by("-count")
            )
            serializer = DorkCountSerializer(dork, many=True)
            return Response({"dorks": serializer.data})
        else:
            dork = (
                Dork.objects.filter(dorks__in=ScanHistory.objects.all())
                .values("type")
                .annotate(count=Count("type"))
                .order_by("-count")
            )
            serializer = DorkCountSerializer(dork, many=True)
            return Response({"dorks": serializer.data})


class ListEmails(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            email = Email.objects.filter(
                emails__in=ScanHistory.objects.filter(id=scan_id)
            ).order_by("password")
            serializer = EmailSerializer(email, many=True)
            return Response({"emails": serializer.data})


class ListDorks(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        type = req.query_params.get("type")
        if scan_id:
            dork = Dork.objects.filter(dorks__in=ScanHistory.objects.filter(id=scan_id))
        else:
            dork = Dork.objects.filter(dorks__in=ScanHistory.objects.all())
        if scan_id and type:
            dork = dork.filter(type=type)
        serializer = DorkSerializer(dork, many=True)
        return Response({"dorks": serializer.data})


class ListEmployees(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            employee = Employee.objects.filter(
                employees__in=ScanHistory.objects.filter(id=scan_id)
            )
            serializer = EmployeeSerializer(employee, many=True)
            return Response({"employees": serializer.data})


class ListPorts(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")
        ip_address = req.query_params.get("ip_address")

        if target_id:
            port = Port.objects.filter(
                ports__in=IpAddress.objects.filter(
                    ip_addresses__in=Subdomain.objects.filter(
                        target_domain__id=target_id
                    )
                )
            ).distinct()
        elif scan_id:
            port = Port.objects.filter(
                ports__in=IpAddress.objects.filter(
                    ip_addresses__in=Subdomain.objects.filter(scan_history__id=scan_id)
                )
            ).distinct()
        else:
            port = Port.objects.filter(
                ports__in=IpAddress.objects.filter(
                    ip_addresses__in=Subdomain.objects.all()
                )
            ).distinct()

        if ip_address:
            port = port.filter(ports__address=ip_address).distinct()

        serializer = PortSerializer(port, many=True)
        return Response({"ports": serializer.data})


class ListSubdomains(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")
        ip_address = req.query_params.get("ip_address")
        port = req.query_params.get("port")
        tech = req.query_params.get("tech")

        if scan_id:
            subdomain_query = Subdomain.objects.filter(
                scan_history__id=scan_id
            ).distinct("name")
        elif target_id:
            subdomain_query = Subdomain.objects.filter(
                target_domain__id=target_id
            ).distinct("name")
        else:
            subdomain_query = Subdomain.objects.all().distinct("name")

        if ip_address:
            subdomain_query = subdomain_query.filter(ip_addresses__address=ip_address)

        if tech:
            subdomain_query = subdomain_query.filter(technologies__name=tech)

        if port:
            subdomain_query = subdomain_query.filter(
                ip_addresses__in=IpAddress.objects.filter(
                    ports__in=Port.objects.filter(number=port)
                )
            )

        if "only_important" in req.query_params:
            subdomain_query = subdomain_query.filter(is_important=True)

        if "no_lookup_interesting" in req.query_params:
            serializer = OnlySubdomainNameSerializer(subdomain_query, many=True)
        else:
            serializer = SubdomainSerializer(subdomain_query, many=True)
        return Response({"subdomains": serializer.data})

    def post(self, req):
        req = self.request
        data = req.data

        subdomain_ids = data.get("subdomain_ids")

        subdomain_names = []

        for id in subdomain_ids:
            subdomain_names.append(Subdomain.objects.get(id=id).name)

        if subdomain_names:
            return Response({"status": True, "results": subdomain_names})

        return Response({"status": False})


class ListOsintUsers(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            documents = (
                MetaFinderDocument.objects.filter(scan_history__id=scan_id)
                .exclude(author__isnull=True)
                .values("author")
                .distinct()
            )
            serializer = MetafinderUserSerializer(documents, many=True)
            return Response({"users": serializer.data})


class ListMetadata(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            documents = MetaFinderDocument.objects.filter(
                scan_history__id=scan_id
            ).distinct()
            serializer = MetafinderDocumentSerializer(documents, many=True)
            return Response({"metadata": serializer.data})


class ListIPs(APIView):
    def get(self, request, format=None):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")

        port = req.query_params.get("port")

        if target_id:
            ips = IpAddress.objects.filter(
                ip_addresses__in=Subdomain.objects.filter(target_domain__id=target_id)
            ).distinct()
        elif scan_id:
            ips = IpAddress.objects.filter(
                ip_addresses__in=Subdomain.objects.filter(scan_history__id=scan_id)
            ).distinct()
        else:
            ips = IpAddress.objects.filter(
                ip_addresses__in=Subdomain.objects.all()
            ).distinct()

        if port:
            ips = ips.filter(ports__in=Port.objects.filter(number=port)).distinct()

        serializer = IpSerializer(ips, many=True)
        return Response({"ips": serializer.data})


class IpAddressViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = IpSubdomainSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")

        if scan_id:
            self.queryset = (
                Subdomain.objects.filter(scan_history__id=scan_id)
                .exclude(ip_addresses__isnull=True)
                .distinct()
            )
        else:
            self.serializer_class = IpSerializer
            self.queryset = Ip.objects.all()
        return self.queryset

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class SubdomainsViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        if scan_id:
            if "only_screenshot" in self.request.query_params:
                return Subdomain.objects.filter(scan_history__id=scan_id).exclude(
                    screenshot_path__isnull=True
                )
            return Subdomain.objects.filter(scan_history=scan_id)

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class SubdomainChangesViewSet(viewsets.ModelViewSet):
    """
    This viewset will return the Subdomain changes
    To get the new subdomains, we will look for ScanHistory with
    subdomain_discovery = True and the status of the last scan has to be
    successful and calculate difference
    """

    queryset = Subdomain.objects.none()
    serializer_class = SubdomainChangesSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        changes = req.query_params.get("changes")
        domain_id = ScanHistory.objects.filter(id=scan_id)[0].domain.id
        scan_history = (
            ScanHistory.objects.filter(domain=domain_id)
            .filter(subdomain_discovery=True)
            .filter(id__lte=scan_id)
            .exclude(Q(scan_status=-1) | Q(scan_status=1))
        )
        if scan_history.count() > 1:
            last_scan = scan_history.order_by("-start_scan_date")[1]
            scanned_host_q1 = Subdomain.objects.filter(scan_history__id=scan_id).values(
                "name"
            )
            scanned_host_q2 = Subdomain.objects.filter(
                scan_history__id=last_scan.id
            ).values("name")
            added_subdomain = scanned_host_q1.difference(scanned_host_q2)
            removed_subdomains = scanned_host_q2.difference(scanned_host_q1)
            if changes == "added":
                return (
                    Subdomain.objects.filter(scan_history=scan_id)
                    .filter(name__in=added_subdomain)
                    .annotate(change=Value("added", output_field=CharField()))
                )
            elif changes == "removed":
                return (
                    Subdomain.objects.filter(scan_history=last_scan)
                    .filter(name__in=removed_subdomains)
                    .annotate(change=Value("removed", output_field=CharField()))
                )
            else:
                added_subdomain = (
                    Subdomain.objects.filter(scan_history=scan_id)
                    .filter(name__in=added_subdomain)
                    .annotate(change=Value("added", output_field=CharField()))
                )
                removed_subdomains = (
                    Subdomain.objects.filter(scan_history=last_scan)
                    .filter(name__in=removed_subdomains)
                    .annotate(change=Value("removed", output_field=CharField()))
                )
                changes = added_subdomain.union(removed_subdomains)
                return changes
        return self.queryset

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class EndPointChangesViewSet(viewsets.ModelViewSet):
    """
    This viewset will return the EndPoint changes
    """

    queryset = EndPoint.objects.none()
    serializer_class = EndPointChangesSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        changes = req.query_params.get("changes")

        domain_id = ScanHistory.objects.filter(id=scan_id)[0].domain.id
        scan_history = (
            ScanHistory.objects.filter(domain=domain_id)
            .filter(fetch_url=True)
            .filter(id__lte=scan_id)
            .filter(scan_status=2)
        )
        if scan_history.count() > 1:
            last_scan = scan_history.order_by("-start_scan_date")[1]
            scanned_host_q1 = EndPoint.objects.filter(scan_history__id=scan_id).values(
                "http_url"
            )
            scanned_host_q2 = EndPoint.objects.filter(
                scan_history__id=last_scan.id
            ).values("http_url")
            added_endpoints = scanned_host_q1.difference(scanned_host_q2)
            removed_endpoints = scanned_host_q2.difference(scanned_host_q1)
            if changes == "added":
                return (
                    EndPoint.objects.filter(scan_history=scan_id)
                    .filter(http_url__in=added_endpoints)
                    .annotate(change=Value("added", output_field=CharField()))
                )
            elif changes == "removed":
                return (
                    EndPoint.objects.filter(scan_history=last_scan)
                    .filter(http_url__in=removed_endpoints)
                    .annotate(change=Value("removed", output_field=CharField()))
                )
            else:
                added_endpoints = (
                    EndPoint.objects.filter(scan_history=scan_id)
                    .filter(http_url__in=added_endpoints)
                    .annotate(change=Value("added", output_field=CharField()))
                )
                removed_endpoints = (
                    EndPoint.objects.filter(scan_history=last_scan)
                    .filter(http_url__in=removed_endpoints)
                    .annotate(change=Value("removed", output_field=CharField()))
                )
                changes = added_endpoints.union(removed_endpoints)
                return changes
        return self.queryset

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class InterestingSubdomainViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")

        if "only_subdomains" in self.request.query_params:
            self.serializer_class = InterestingSubdomainSerializer

        if scan_id:
            self.queryset = get_interesting_subdomains(scan_history=scan_id)
        elif target_id:
            self.queryset = get_interesting_subdomains(target=target_id)
        else:
            self.queryset = get_interesting_subdomains()

        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        order_col = "content_length"
        if _order_col == "0":
            order_col = "name"
        elif _order_col == "1":
            order_col = "page_title"
        elif _order_col == "2":
            order_col = "http_status"
        elif _order_col == "3":
            order_col = "content_length"

        if _order_direction == "desc":
            order_col = "-{}".format(order_col)

        if search_value:
            qs = self.queryset.filter(
                Q(name__icontains=search_value)
                | Q(page_title__icontains=search_value)
                | Q(http_status__icontains=search_value)
            )
        return qs.order_by(order_col)

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class InterestingEndpointViewSet(viewsets.ModelViewSet):
    queryset = EndPoint.objects.none()
    serializer_class = EndpointSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")
        if "only_endpoints" in self.request.query_params:
            self.serializer_class = InterestingEndPointSerializer
        if scan_id:
            return get_interesting_endpoint(scan_history=scan_id)
        elif target_id:
            return get_interesting_endpoint(target=target_id)
        else:
            return get_interesting_endpoint()

    def paginate_queryset(self, queryset, view=None):
        if "no_page" in self.request.query_params:
            return None
        return self.paginator.paginate_queryset(queryset, self.request, view=self)


class SubdomainDatatableViewSet(viewsets.ModelViewSet):
    queryset = Subdomain.objects.none()
    serializer_class = SubdomainSerializer

    def get_queryset(self):
        req = self.request
        scan_id = req.query_params.get("scan_id")

        target_id = req.query_params.get("target_id")

        url_query = req.query_params.get("query_param")

        ip_address = req.query_params.get("ip_address")

        name = req.query_params.get("name")

        if target_id:
            self.queryset = Subdomain.objects.filter(
                target_domain__id=target_id
            ).distinct()
        elif url_query:
            self.queryset = Subdomain.objects.filter(
                Q(target_domain__name=url_query)
            ).distinct()
        elif scan_id:
            self.queryset = Subdomain.objects.filter(
                scan_history__id=scan_id
            ).distinct()
        else:
            self.queryset = Subdomain.objects.distinct()

        if "only_directory" in req.query_params:
            self.queryset = self.queryset.exclude(directories__isnull=True)

        if ip_address:
            self.queryset = self.queryset.filter(
                ip_addresses__address__icontains=ip_address
            )

        if name:
            self.queryset = self.queryset.filter(name=name)

        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        order_col = "content_length"
        if _order_col == "0":
            order_col = "checked"
        elif _order_col == "1":
            order_col = "name"
        elif _order_col == "4":
            order_col = "http_status"
        elif _order_col == "5":
            order_col = "page_title"
        elif _order_col == "8":
            order_col = "content_length"
        elif _order_col == "10":
            order_col = "response_time"
        if _order_direction == "desc":
            order_col = "-{}".format(order_col)
        # if the search query is separated by = means, it is a specific lookup
        # divide the search query into two half and lookup
        if search_value:
            if (
                "=" in search_value
                or "&" in search_value
                or "|" in search_value
                or ">" in search_value
                or "<" in search_value
                or "!" in search_value
            ):
                if "&" in search_value:
                    complex_query = search_value.split("&")
                    for query in complex_query:
                        if query.strip():
                            qs = qs & self.special_lookup(query.strip())
                elif "|" in search_value:
                    qs = Subdomain.objects.none()
                    complex_query = search_value.split("|")
                    for query in complex_query:
                        if query.strip():
                            qs = self.special_lookup(query.strip()) | qs
                else:
                    qs = self.special_lookup(search_value)
            else:
                qs = self.general_lookup(search_value)
        return qs.order_by(order_col)

    def general_lookup(self, search_value):
        qs = self.queryset.filter(
            Q(name__icontains=search_value)
            | Q(cname__icontains=search_value)
            | Q(http_status__icontains=search_value)
            | Q(page_title__icontains=search_value)
            | Q(http_url__icontains=search_value)
            | Q(technologies__name__icontains=search_value)
            | Q(webserver__icontains=search_value)
            | Q(ip_addresses__address__icontains=search_value)
            | Q(ip_addresses__ports__number__icontains=search_value)
            | Q(ip_addresses__ports__service_name__icontains=search_value)
            | Q(ip_addresses__ports__description__icontains=search_value)
        )

        if "only_directory" in self.request.query_params:
            print("Okay")
            qs = qs | self.queryset.filter(
                Q(directories__directory_files__name__icontains=search_value)
            )

        return qs

    def special_lookup(self, search_value):
        qs = self.queryset.filter()
        if "=" in search_value:
            search_param = search_value.split("=")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "name" in lookup_title:
                qs = self.queryset.filter(name__icontains=lookup_content)
            elif "page_title" in lookup_title:
                qs = self.queryset.filter(page_title__icontains=lookup_content)
            elif "http_url" in lookup_title:
                qs = self.queryset.filter(http_url__icontains=lookup_content)
            elif "content_type" in lookup_title:
                qs = self.queryset.filter(content_type__icontains=lookup_content)
            elif "cname" in lookup_title:
                qs = self.queryset.filter(cname__icontains=lookup_content)
            elif "webserver" in lookup_title:
                qs = self.queryset.filter(webserver__icontains=lookup_content)
            elif "ip_addresses" in lookup_title:
                qs = self.queryset.filter(
                    ip_addresses__address__icontains=lookup_content
                )
            elif "is_important" in lookup_title:
                if "true" in lookup_content.lower():
                    qs = self.queryset.filter(is_important=True)
                else:
                    qs = self.queryset.filter(is_important=False)
            elif "port" in lookup_title:
                qs = (
                    self.queryset.filter(
                        ip_addresses__ports__number__icontains=lookup_content
                    )
                    | self.queryset.filter(
                        ip_addresses__ports__service_name__icontains=lookup_content
                    )
                    | self.queryset.filter(
                        ip_addresses__ports__description__icontains=lookup_content
                    )
                )
            elif "technology" in lookup_title:
                qs = self.queryset.filter(technologies__name__icontains=lookup_content)
            elif "http_status" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.filter(http_status=int_http_status)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.filter(content_length=int_http_status)
                except Exception as e:
                    print(e)
        elif ">" in search_value:
            search_param = search_value.split(">")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "http_status" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(http_status__gt=int_val)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(content_length__gt=int_val)
                except Exception as e:
                    print(e)
        elif "<" in search_value:
            search_param = search_value.split("<")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "http_status" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(http_status__lt=int_val)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(content_length__lt=int_val)
                except Exception as e:
                    print(e)
        elif "!" in search_value:
            search_param = search_value.split("!")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "name" in lookup_title:
                qs = self.queryset.exclude(name__icontains=lookup_content)
            elif "page_title" in lookup_title:
                qs = self.queryset.exclude(page_title__icontains=lookup_content)
            elif "http_url" in lookup_title:
                qs = self.queryset.exclude(http_url__icontains=lookup_content)
            elif "content_type" in lookup_title:
                qs = self.queryset.exclude(content_type__icontains=lookup_content)
            elif "cname" in lookup_title:
                qs = self.queryset.exclude(cname__icontains=lookup_content)
            elif "webserver" in lookup_title:
                qs = self.queryset.exclude(webserver__icontains=lookup_content)
            elif "ip_addresses" in lookup_title:
                qs = self.queryset.exclude(
                    ip_addresses__address__icontains=lookup_content
                )
            elif "port" in lookup_title:
                qs = (
                    self.queryset.exclude(
                        ip_addresses__ports__number__icontains=lookup_content
                    )
                    | self.queryset.exclude(
                        ip_addresses__ports__service_name__icontains=lookup_content
                    )
                    | self.queryset.exclude(
                        ip_addresses__ports__description__icontains=lookup_content
                    )
                )
            elif "technology" in lookup_title:
                qs = self.queryset.exclude(technologies__name__icontains=lookup_content)
            elif "http_status" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.exclude(http_status=int_http_status)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.exclude(content_length=int_http_status)
                except Exception as e:
                    print(e)

        return qs


class ListEndpoints(APIView):
    def get(self, request, format=None):
        req = self.request

        scan_id = req.query_params.get("scan_id")
        target_id = req.query_params.get("target_id")
        subdomain_name = req.query_params.get("subdomain_name")
        pattern = req.query_params.get("pattern")

        if scan_id:
            endpoints = EndPoint.objects.filter(scan_history__id=scan_id)
        elif target_id:
            endpoints = EndPoint.objects.filter(target_domain__id=target_id).distinct()
        else:
            endpoints = EndPoint.objects.all()

        if subdomain_name:
            endpoints = endpoints.filter(subdomain__name=subdomain_name)

        if pattern:
            endpoints = endpoints.filter(matched_gf_patterns__icontains=pattern)

        if "only_urls" in req.query_params:
            endpoints_serializer = EndpointOnlyURLsSerializer(endpoints, many=True)

        else:
            endpoints_serializer = EndpointSerializer(endpoints, many=True)

        return Response({"endpoints": endpoints_serializer.data})


class EndPointViewSet(viewsets.ModelViewSet):
    queryset = EndPoint.objects.none()
    serializer_class = EndpointSerializer

    def get_queryset(self):
        req = self.request

        scan_id = req.query_params.get("scan_history")
        target_id = req.query_params.get("target_id")
        url_query = req.query_params.get("query_param")
        subdomain_id = req.query_params.get("subdomain_id")

        gf_tag = (
            req.query_params.get("gf_tag") if "gf_tag" in req.query_params else None
        )

        if scan_id:
            endpoints_queryset = EndPoint.objects.filter(
                scan_history__id=scan_id
            ).distinct()
        elif target_id:
            endpoints_queryset = EndPoint.objects.filter(
                target_domain__id=target_id
            ).distinct()
        else:
            endpoints_queryset = EndPoint.objects.distinct()

        if url_query:
            endpoints_queryset = endpoints_queryset.filter(
                Q(target_domain__name=url_query)
            ).distinct()

        if gf_tag:
            endpoints_queryset = endpoints_queryset.filter(
                matched_gf_patterns__icontains=gf_tag
            )

        if subdomain_id:
            endpoints_queryset = endpoints_queryset.filter(subdomain__id=subdomain_id)

        if "only_urls" in req.query_params:
            self.serializer_class = EndpointOnlyURLsSerializer

        self.queryset = endpoints_queryset

        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        if search_value or _order_col or _order_direction:
            order_col = "content_length"
            if _order_col == "1":
                order_col = "http_url"
            elif _order_col == "2":
                order_col = "http_status"
            elif _order_col == "3":
                order_col = "page_title"
            elif _order_col == "4":
                order_col = "matched_gf_patterns"
            elif _order_col == "5":
                order_col = "content_type"
            elif _order_col == "6":
                order_col = "content_length"
            elif _order_col == "7":
                order_col = "technologies"
            elif _order_col == "8":
                order_col = "webserver"
            elif _order_col == "9":
                order_col = "response_time"
            if _order_direction == "desc":
                order_col = "-{}".format(order_col)
            # if the search query is separated by = means, it is a specific lookup
            # divide the search query into two half and lookup
            if (
                "=" in search_value
                or "&" in search_value
                or "|" in search_value
                or ">" in search_value
                or "<" in search_value
                or "!" in search_value
            ):
                if "&" in search_value:
                    complex_query = search_value.split("&")
                    for query in complex_query:
                        if query.strip():
                            qs = qs & self.special_lookup(query.strip())
                elif "|" in search_value:
                    qs = Subdomain.objects.none()
                    complex_query = search_value.split("|")
                    for query in complex_query:
                        if query.strip():
                            qs = self.special_lookup(query.strip()) | qs
                else:
                    qs = self.special_lookup(search_value)
            else:
                qs = self.general_lookup(search_value)
            return qs.order_by(order_col)
        return qs

    def general_lookup(self, search_value):
        qs = self.queryset.filter(
            Q(http_url__icontains=search_value)
            | Q(page_title__icontains=search_value)
            | Q(http_status__icontains=search_value)
            | Q(content_type__icontains=search_value)
            | Q(webserver__icontains=search_value)
            | Q(technologies__name__icontains=search_value)
            | Q(content_type__icontains=search_value)
            | Q(matched_gf_patterns__icontains=search_value)
        )

        return qs

    def special_lookup(self, search_value):
        qs = self.queryset.filter()
        if "=" in search_value:
            search_param = search_value.split("=")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "http_url" in lookup_title:
                qs = self.queryset.filter(http_url__icontains=lookup_content)
            elif "page_title" in lookup_title:
                qs = self.queryset.filter(page_title__icontains=lookup_content)
            elif "content_type" in lookup_title:
                qs = self.queryset.filter(content_type__icontains=lookup_content)
            elif "webserver" in lookup_title:
                qs = self.queryset.filter(webserver__icontains=lookup_content)
            elif "technology" in lookup_title:
                qs = self.queryset.filter(technologies__name__icontains=lookup_content)
            elif "gf_pattern" in lookup_title:
                qs = self.queryset.filter(matched_gf_patterns__icontains=lookup_content)
            elif "http_status" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.filter(http_status=int_http_status)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.filter(content_length=int_http_status)
                except Exception as e:
                    print(e)
        elif ">" in search_value:
            search_param = search_value.split(">")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "http_status" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(http_status__gt=int_val)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(content_length__gt=int_val)
                except Exception as e:
                    print(e)
        elif "<" in search_value:
            search_param = search_value.split("<")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "http_status" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(http_status__lt=int_val)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_val = int(lookup_content)
                    qs = self.queryset.filter(content_length__lt=int_val)
                except Exception as e:
                    print(e)
        elif "!" in search_value:
            search_param = search_value.split("!")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "http_url" in lookup_title:
                qs = self.queryset.exclude(http_url__icontains=lookup_content)
            elif "page_title" in lookup_title:
                qs = self.queryset.exclude(page_title__icontains=lookup_content)
            elif "content_type" in lookup_title:
                qs = self.queryset.exclude(content_type__icontains=lookup_content)
            elif "webserver" in lookup_title:
                qs = self.queryset.exclude(webserver__icontains=lookup_content)
            elif "technology" in lookup_title:
                qs = self.queryset.exclude(technologies__name__icontains=lookup_content)
            elif "gf_pattern" in lookup_title:
                qs = self.queryset.exclude(
                    matched_gf_patterns__icontains=lookup_content
                )
            elif "http_status" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.exclude(http_status=int_http_status)
                except Exception as e:
                    print(e)
            elif "content_length" in lookup_title:
                try:
                    int_http_status = int(lookup_content)
                    qs = self.queryset.exclude(content_length=int_http_status)
                except Exception as e:
                    print(e)
        return qs


class DirectoryViewSet(viewsets.ModelViewSet):
    queryset = DirectoryFile.objects.none()
    serializer_class = DirectoryFileSerializer

    def get_queryset(self):
        req = self.request

        scan_id = req.query_params.get("scan_history")
        subdomain_id = req.query_params.get("subdomain_id")

        if scan_id:
            dirs_queryset = DirectoryFile.objects.filter(
                directory_files__in=DirectoryScan.objects.filter(
                    directories__in=Subdomain.objects.filter(scan_history__id=scan_id)
                )
            ).distinct()
        else:
            dirs_queryset = DirectoryFile.objects.distinct()

        print(dirs_queryset)

        if subdomain_id:
            dirs_queryset = DirectoryFile.objects.filter(
                directory_files__in=DirectoryScan.objects.filter(
                    directories__in=Subdomain.objects.filter(id=subdomain_id)
                )
            ).distinct()

        self.queryset = dirs_queryset

        return self.queryset


class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.none()
    serializer_class = VulnerabilitySerializer

    def get_queryset(self):
        req = self.request

        scan_id = req.query_params.get("scan_history")
        target_id = req.query_params.get("target_id")
        domain = req.query_params.get("domain")
        severity = req.query_params.get("severity")
        subdomain_id = req.query_params.get("subdomain_id")
        subdomain_name = req.query_params.get("subdomain")
        vulnerability_name = req.query_params.get("vulnerability_name")

        if scan_id:
            vulnerability_queryset = Vulnerability.objects.filter(
                scan_history__id=scan_id
            ).distinct()
        elif target_id:
            vulnerability_queryset = Vulnerability.objects.filter(
                target_domain__id=target_id
            ).distinct()
        elif subdomain_name:
            vulnerability_queryset = Vulnerability.objects.filter(
                subdomain__in=Subdomain.objects.filter(name=subdomain_name)
            ).distinct()
        else:
            vulnerability_queryset = Vulnerability.objects.distinct()

        if domain:
            vulnerability_queryset = vulnerability_queryset.filter(
                Q(target_domain__name=domain)
            ).distinct()

        if vulnerability_name:
            vulnerability_queryset = vulnerability_queryset.filter(
                Q(name=vulnerability_name)
            ).distinct()

        if severity:
            vulnerability_queryset = vulnerability_queryset.filter(severity=severity)

        if subdomain_id:
            vulnerability_queryset = vulnerability_queryset.filter(
                subdomain__id=subdomain_id
            )

        self.queryset = vulnerability_queryset

        return self.queryset

    def filter_queryset(self, qs):
        qs = self.queryset.filter()
        search_value = self.request.GET.get("search[value]", None)
        _order_col = self.request.GET.get("order[0][column]", None)
        _order_direction = self.request.GET.get("order[0][dir]", None)
        if search_value or _order_col or _order_direction:
            order_col = "severity"
            if _order_col == "0" or _order_col == "14":
                order_col = "open_status"
            elif _order_col == "1":
                order_col = "type"
            elif _order_col == "2":
                order_col = "name"
            elif _order_col == "6":
                order_col = "severity"
            elif _order_col == "7":
                order_col = "cvss_score"
            elif _order_col == "10":
                order_col = "http_url"
            elif _order_col == "13":
                order_col = "discovered_date"
            if _order_direction == "desc":
                order_col = "-{}".format(order_col)
            # if the search query is separated by = means, it is a specific lookup
            # divide the search query into two half and lookup
            if (
                "=" in search_value
                or "&" in search_value
                or "|" in search_value
                or ">" in search_value
                or "<" in search_value
                or "!" in search_value
            ):
                if "&" in search_value:
                    complex_query = search_value.split("&")
                    for query in complex_query:
                        if query.strip():
                            qs = qs & self.special_lookup(query.strip())
                elif "|" in search_value:
                    qs = Subdomain.objects.none()
                    complex_query = search_value.split("|")
                    for query in complex_query:
                        if query.strip():
                            qs = self.special_lookup(query.strip()) | qs
                else:
                    qs = self.special_lookup(search_value)
            else:
                qs = self.general_lookup(search_value)
            return qs.order_by(order_col)
        return qs.order_by("-severity")

    def general_lookup(self, search_value):
        qs = self.queryset.filter(
            Q(http_url__icontains=search_value)
            | Q(target_domain__name__icontains=search_value)
            | Q(template__icontains=search_value)
            | Q(template_id__icontains=search_value)
            | Q(name__icontains=search_value)
            | Q(severity__icontains=search_value)
            | Q(description__icontains=search_value)
            | Q(extracted_results__icontains=search_value)
            | Q(references__url__icontains=search_value)
            | Q(cve_ids__name__icontains=search_value)
            | Q(cwe_ids__name__icontains=search_value)
            | Q(cvss_metrics__icontains=search_value)
            | Q(cvss_score__icontains=search_value)
            | Q(type__icontains=search_value)
            | Q(open_status__icontains=search_value)
            | Q(hackerone_report_id__icontains=search_value)
            | Q(tags__name__icontains=search_value)
        )
        return qs

    def special_lookup(self, search_value):
        qs = self.queryset.filter()
        if "=" in search_value:
            search_param = search_value.split("=")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "severity" in lookup_title:
                severity_value = ""
                if lookup_content == "info":
                    severity_value = 0
                elif lookup_content == "low":
                    severity_value = 1
                elif lookup_content == "medium":
                    severity_value = 2
                elif lookup_content == "high":
                    severity_value = 3
                elif lookup_content == "critical":
                    severity_value = 4
                elif lookup_content == "unknown":
                    severity_value = -1
                if severity_value:
                    qs = self.queryset.filter(severity=severity_value)
            elif "name" in lookup_title:
                qs = self.queryset.filter(name__icontains=lookup_content)
            elif "http_url" in lookup_title:
                qs = self.queryset.filter(http_url__icontains=lookup_content)
            elif "template" in lookup_title:
                qs = self.queryset.filter(template__icontains=lookup_content)
            elif "template_id" in lookup_title:
                qs = self.queryset.filter(template_id__icontains=lookup_content)
            elif "cve_id" in lookup_title or "cve" in lookup_title:
                qs = self.queryset.filter(cve_ids__name__icontains=lookup_content)
            elif "cwe_id" in lookup_title or "cwe" in lookup_title:
                qs = self.queryset.filter(cwe_ids__name__icontains=lookup_content)
            elif "cvss_metrics" in lookup_title:
                qs = self.queryset.filter(cvss_metrics__icontains=lookup_content)
            elif "cvss_score" in lookup_title:
                qs = self.queryset.filter(cvss_score__exact=lookup_content)
            elif "type" in lookup_title:
                qs = self.queryset.filter(type__icontains=lookup_content)
            elif "tag" in lookup_title:
                qs = self.queryset.filter(tags__name__icontains=lookup_content)
            elif "status" in lookup_title:
                if lookup_content == "open":
                    qs = self.queryset.filter(open_status=True)
                elif lookup_content == "closed":
                    qs = self.queryset.filter(open_status=False)
            elif "description" in lookup_title:
                qs = self.queryset.filter(
                    Q(description__icontains=lookup_content)
                    | Q(template__icontains=lookup_content)
                    | Q(extracted_results__icontains=lookup_content)
                )
        elif "!" in search_value:
            search_param = search_value.split("!")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "severity" in lookup_title:
                severity_value = ""
                if lookup_content == "info":
                    severity_value = 0
                elif lookup_content == "low":
                    severity_value = 1
                elif lookup_content == "medium":
                    severity_value = 2
                elif lookup_content == "high":
                    severity_value = 3
                elif lookup_content == "critical":
                    severity_value = 4
                elif lookup_content == "unknown":
                    severity_value = -1
                if severity_value:
                    qs = self.queryset.exclude(severity=severity_value)
            elif "name" in lookup_title:
                qs = self.queryset.exclude(name__icontains=lookup_content)
            elif "http_url" in lookup_title:
                qs = self.queryset.exclude(http_url__icontains=lookup_content)
            elif "template" in lookup_title:
                qs = self.queryset.exclude(template__icontains=lookup_content)
            elif "template_id" in lookup_title:
                qs = self.queryset.exclude(template_id__icontains=lookup_content)
            elif "cve_id" in lookup_title or "cve" in lookup_title:
                qs = self.queryset.exclude(cve_ids__icontains=lookup_content)
            elif "cwe_id" in lookup_title or "cwe" in lookup_title:
                qs = self.queryset.exclude(cwe_ids__icontains=lookup_content)
            elif "cvss_metrics" in lookup_title:
                qs = self.queryset.exclude(cvss_metrics__icontains=lookup_content)
            elif "cvss_score" in lookup_title:
                qs = self.queryset.exclude(cvss_score__exact=lookup_content)
            elif "type" in lookup_title:
                qs = self.queryset.exclude(type__icontains=lookup_content)
            elif "tag" in lookup_title:
                qs = self.queryset.exclude(tags__icontains=lookup_content)
            elif "status" in lookup_title:
                if lookup_content == "open":
                    qs = self.queryset.exclude(open_status=True)
                elif lookup_content == "closed":
                    qs = self.queryset.exclude(open_status=False)
            elif "description" in lookup_title:
                qs = self.queryset.exclude(
                    Q(description__icontains=lookup_content)
                    | Q(template__icontains=lookup_content)
                    | Q(extracted_results__icontains=lookup_content)
                )
        elif ">" in search_value:
            search_param = search_value.split(">")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "cvss_score" in lookup_title:
                try:
                    val = float(lookup_content)
                    qs = self.queryset.filter(cvss_score__gt=val)
                except Exception as e:
                    print(e)
        elif "<" in search_value:
            search_param = search_value.split("<")
            lookup_title = search_param[0].lower().strip()
            lookup_content = search_param[1].lower().strip()
            if "cvss_score" in lookup_title:
                try:
                    val = int(lookup_content)
                    qs = self.queryset.filter(cvss_score__lt=val)
                except Exception as e:
                    print(e)
        return qs
