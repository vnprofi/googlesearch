import sys
import os
import subprocess
import platform
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QWidget, QLabel, QLineEdit, QPushButton, QTextEdit,
                             QSpinBox, QCheckBox, QProgressBar, QFileDialog,
                             QMessageBox, QGroupBox, QGridLayout, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QUrl
from PyQt5.QtGui import QFont, QIcon, QDesktopServices
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import pandas as pd
import time
import random
import re
import threading
import traceback
from typing import Dict, Optional, List
from urllib.parse import urlparse
from function import ManualGoogleSession

# РќР°СЃС‚СЂРѕР№РєР° РїСѓС‚Рё Рє Р±СЂР°СѓР·РµСЂР°Рј Playwright
# РљРѕСЂСЂРµРєС‚РЅРѕ СЂР°Р±РѕС‚Р°РµС‚ РєР°Рє РёР· РёСЃС…РѕРґРЅРёРєРѕРІ, С‚Р°Рє Рё РёР· СѓРїР°РєРѕРІР°РЅРЅРѕРіРѕ PyInstaller-exe
# РћРїСЂРµРґРµР»СЏРµРј Р±Р°Р·РѕРІС‹Р№ РєР°С‚Р°Р»РѕРі: РІ СЃРѕР±СЂР°РЅРЅРѕРј onefile PyInstaller РґР°РЅРЅС‹Рµ СЂР°СЃРїР°РєРѕРІС‹РІР°СЋС‚СЃСЏ
# РІРѕ РІСЂРµРјРµРЅРЅСѓСЋ РїР°РїРєСѓ, РїСѓС‚СЊ Рє РєРѕС‚РѕСЂРѕР№ С…СЂР°РЅРёС‚СЃСЏ РІ sys._MEIPASS. РСЃРїРѕР»СЊР·СѓРµРј РµРіРѕ, С‡С‚РѕР±С‹
# РЅР°Р№С‚Рё РІСЃС‚СЂРѕРµРЅРЅСѓСЋ РїР°РїРєСѓ ms-playwright.
if getattr(sys, 'frozen', False):
    # Р’ onefile-СЂРµР¶РёРјРµ PyInstaller СЃРѕР·РґР°С‘С‚ РІСЂРµРјРµРЅРЅСѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ _MEI***
    base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))

if platform.system() == "Darwin":  # macOS
    # Р”Р»СЏ macOS Р±СЂР°СѓР·РµСЂС‹ Playwright РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ СѓСЃС‚Р°РЅР°РІР»РёРІР°СЋС‚СЃСЏ РІ РєРµС€ РїРѕР»СЊР·РѕРІР°С‚РµР»СЏ
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.expanduser("~/Library/Caches/ms-playwright")
else:  # Windows/Linux
    # РС‰РµРј РєР°С‚Р°Р»РѕРі ms-playwright СЂСЏРґРѕРј СЃ РёСЃРїРѕР»РЅСЏРµРјС‹Рј С„Р°Р№Р»РѕРј
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = os.path.join(base_dir, "ms-playwright")

WHOIS_REQUEST_DELAY = 1.0

def extract_domain_from_url(url: str) -> Optional[str]:
    """РР·РІР»РµРєР°РµС‚ С‡РёСЃС‚С‹Р№ РґРѕРјРµРЅ РёР· СЃС‚СЂРѕРєРё URL/С†РёС‚Р°С†РёРё."""
    if not url:
        return None
    try:
        # РћР±СЂР°Р±РѕС‚РєР° С„РѕСЂРјР°С‚Р° С‚РёРїР° "example.com вЂє contacts"
        if 'вЂє' in url:
            url = url.split('вЂє')[0].strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        if '.' not in domain or len(domain) < 4:
            return None
        return domain.lower()
    except Exception:
        return None

def get_whois_data(domain: str) -> Dict[str, Optional[str]]:
    """РџРѕР»СѓС‡Р°РµС‚ РґР°РЅРЅС‹Рµ WHOIS РґР»СЏ РґРѕРјРµРЅР° С‡РµСЂРµР· whois.ru СЃ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёРµРј Р±СЂР°СѓР·РµСЂР°."""
    whois_data = {
        'domain': domain,
        'citation_index': None,
        'alexa_rating': None,
        'registrar': None,
        'registration_date': None,
        'expiration_date': None,
        'days_until_expiration': None,
        'check_date': None,
        'external_links': None,
        'internal_links': None,
        'total_anchors': None,
        'outgoing_anchors': None,
        'domain_links': None,
        'page_title': None,
        'page_description': None,
        'whois_error': None
    }
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            whois_url = f'https://whois.ru/{domain}'
            page.goto(whois_url, wait_until='domcontentloaded')
            try:
                page.wait_for_selector('.list-group-item', timeout=10000)
            except:
                try:
                    button = page.query_selector('#whois_btn')
                    if button:
                        button.click()
                        page.wait_for_selector('.list-group-item', timeout=10000)
                except:
                    pass
            html_content = page.content()
            browser.close()

        soup = BeautifulSoup(html_content, 'html.parser')
        list_groups = soup.find_all('ul', class_='list-group')
        for ul in list_groups:
            items = ul.find_all('li', class_='list-group-item')
            for item in items:
                text = item.get_text().strip()
                strong = item.find('strong')
                if not strong:
                    continue
                value = strong.get_text().strip()
                if 'РРЅРґРµРєСЃ С†РёС‚РёСЂРѕРІР°РЅРёСЏ' in text:
                    whois_data['citation_index'] = value
                elif 'Р РµР№С‚РёРЅРі Alexa' in text:
                    whois_data['alexa_rating'] = value
                elif 'Р РµРіРёСЃС‚СЂР°С‚РѕСЂ РґРѕРјРµРЅР°' in text:
                    whois_data['registrar'] = value
                elif 'Р”Р°С‚Р° СЂРµРіРёСЃС‚СЂР°С†РёРё' in text:
                    whois_data['registration_date'] = value
                elif 'Р”Р°С‚Р° РѕРєРѕРЅС‡Р°РЅРёСЏ' in text:
                    whois_data['expiration_date'] = value
                elif 'Р—Р°РєРѕРЅС‡РёС‚СЃСЏ С‡РµСЂРµР·' in text:
                    whois_data['days_until_expiration'] = value
                elif 'Р”Р°С‚Р° РїСЂРѕРІРµСЂРєРё' in text:
                    whois_data['check_date'] = value
                elif 'Р’РЅРµС€РЅРёРµ СЃСЃС‹Р»РєРё РґРѕРјРµРЅР°' in text:
                    whois_data['external_links'] = value
                elif 'Р’РЅСѓС‚СЂРµРЅРЅРёРµ СЃСЃС‹Р»РєРё' in text:
                    whois_data['internal_links'] = value
                elif 'РљРѕР»-РІРѕ РЅР°Р№РґРµРЅРЅС‹С… Р°РЅРєРѕСЂРѕРІ' in text:
                    whois_data['total_anchors'] = value
                elif 'РљРѕР»-РІРѕ РёСЃС…РѕРґСЏС‰РёС… Р°РЅРєРѕСЂРѕРІ' in text:
                    whois_data['outgoing_anchors'] = value
                elif 'РљРѕР»-РІРѕ СЃСЃС‹Р»РѕРє РЅР° РґРѕРјРµРЅРµ' in text:
                    whois_data['domain_links'] = value
                elif 'Title СЃС‚СЂР°РЅРёС†С‹' in text:
                    whois_data['page_title'] = value
                elif 'Description СЃС‚СЂР°РЅРёС†С‹' in text:
                    whois_data['page_description'] = value

        time.sleep(WHOIS_REQUEST_DELAY)
    except Exception as e:
        whois_data['whois_error'] = f'Error: {str(e)}'
    return whois_data

class GoogleSearchWorker(QThread):
    """Worker thread РґР»СЏ РІС‹РїРѕР»РЅРµРЅРёСЏ РїРѕРёСЃРєР° РІ С„РѕРЅРѕРІРѕРј СЂРµР¶РёРјРµ"""
    progress_updated = pyqtSignal(str)
    results_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)
    captcha_detected = pyqtSignal(int)

    def __init__(self, query, page_from, page_to, parse_all_pages, collect_contacts, results_per_page, profile_dir):
        super().__init__()
        self.query = query
        self.page_from = page_from
        self.page_to = page_to
        self.parse_all_pages = parse_all_pages
        self.collect_contacts = collect_contacts
        self.results_per_page = results_per_page
        self.profile_dir = profile_dir
        self.is_running = True
        self.captcha_resume_event = threading.Event()
        self.captcha_resume_event.set()

    def stop(self):
        self.is_running = False
        self.captcha_resume_event.set()

    def resume_after_captcha(self):
        self.captcha_resume_event.set()

    def emit_progress(self, message):
        if self.is_running:
            self.progress_updated.emit(message)

    def is_captcha_page(self, page):
        try:
            url = page.url.lower()
            return (
                'captcha' in url or
                '/sorry/' in url or
                'sorry/index' in url or
                page.locator('text=РЇ РЅРµ СЂРѕР±РѕС‚').count() > 0 or
                page.locator('form[action*=\"sorry\"]').count() > 0
            )
        except Exception:
            return False

    def wait_for_captcha_resolution(self, page_number):
        self.emit_progress(
            f"РћР±РЅР°СЂСѓР¶РµРЅР° РєР°РїС‡Р° РЅР° СЃС‚СЂР°РЅРёС†Рµ {page_number}. Р РµС€РёС‚Рµ РєР°РїС‡Сѓ РІ РѕС‚РєСЂС‹С‚РѕРј РѕРєРЅРµ Р±СЂР°СѓР·РµСЂР° "
            f"Рё РЅР°Р¶РјРёС‚Рµ РєРЅРѕРїРєСѓ 'РџСЂРѕРґРѕР»Р¶РёС‚СЊ РїРѕСЃР»Рµ РєР°РїС‡Рё'."
        )
        self.captcha_resume_event.clear()
        self.captcha_detected.emit(page_number)
        while self.is_running and not self.captcha_resume_event.wait(0.5):
            pass
        return self.is_running

    def extract_contacts(self, page_content, page=None):
        """РР·РІР»РµРєР°РµС‚ С‚РѕР»СЊРєРѕ email РёР· HTML СЃС‚СЂР°РЅРёС†С‹"""
        soup = BeautifulSoup(page_content, 'html.parser')
        contacts = {'emails': []}
        # РР·РІР»РµРєР°РµРј email СЃ СѓР»СѓС‡С€РµРЅРЅС‹Рј РїР°С‚С‚РµСЂРЅРѕРј
        email_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b'
        emails = re.findall(email_pattern, page_content, re.IGNORECASE)
        # РЎРѕР±РёСЂР°РµРј РїРѕР»РЅС‹Рµ email Р°РґСЂРµСЃР°
        full_emails = []
        for match in re.finditer(email_pattern, page_content, re.IGNORECASE):
            full_emails.append(match.group(0))
        contacts['emails'] = list(set(full_emails))
        return contacts

    def fetch_page_contacts(self, url, page):
        """РџРѕР»СѓС‡Р°РµС‚ РєРѕРЅС‚Р°РєС‚С‹ СЃ РѕРґРЅРѕР№ СЃС‚СЂР°РЅРёС†С‹"""
        try:
            # РџРµСЂРµС…РѕРґРёРј РЅР° СЃС‚СЂР°РЅРёС†Сѓ
            page.goto(url, wait_until='domcontentloaded', timeout=20000)
            # Р–РґРµРј РґРѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕР№ Р·Р°РіСЂСѓР·РєРё
            time.sleep(random.uniform(2, 4))
            # РџС‹С‚Р°РµРјСЃСЏ РґРѕР¶РґР°С‚СЊСЃСЏ Р·Р°РіСЂСѓР·РєРё РґРёРЅР°РјРёС‡РµСЃРєРѕРіРѕ РєРѕРЅС‚РµРЅС‚Р°
            try:
                page.wait_for_load_state('networkidle', timeout=10000)
            except:
                pass
            # РЎРєСЂРѕР»Р»РёРј СЃС‚СЂР°РЅРёС†Сѓ С‡С‚РѕР±С‹ Р·Р°РіСЂСѓР·РёС‚СЊ Р»РµРЅРёРІС‹Р№ РєРѕРЅС‚РµРЅС‚
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(1)
                page.evaluate("window.scrollTo(0, 0)")
            except:
                pass
            # РџРѕР»СѓС‡Р°РµРј РїРѕР»РЅС‹Р№ HTML РїРѕСЃР»Рµ Р·Р°РіСЂСѓР·РєРё
            full_content = page.content()
            # Р”РѕРїРѕР»РЅРёС‚РµР»СЊРЅРѕ РёС‰РµРј РІ СЃРїРµС†РёС„РёС‡РЅС‹С… СЌР»РµРјРµРЅС‚Р°С…
            additional_content = ""
            # РС‰РµРј РІ footer, header, РєРѕРЅС‚Р°РєС‚РЅС‹С… СЃРµРєС†РёСЏС…
            selectors = [
                'footer', 'header', '[class*="contact"]', '[class*="footer"]',
                '[class*="header"]', '[id*="contact"]', '[id*="footer"]',
                '[id*="header"]', '.contacts', '.contact-info', '.contact-us'
            ]
            for selector in selectors:
                try:
                    elements = page.locator(selector).all()
                    for element in elements:
                        try:
                            text = element.inner_html()
                            if text:
                                additional_content += text + " "
                        except:
                            continue
                except:
                    continue
            # РћР±СЉРµРґРёРЅСЏРµРј РІРµСЃСЊ РєРѕРЅС‚РµРЅС‚
            combined_content = full_content + " " + additional_content
            # РР·РІР»РµРєР°РµРј РєРѕРЅС‚Р°РєС‚С‹
            contacts = self.extract_contacts(combined_content, page)
            return contacts
        except Exception as e:
            self.emit_progress(f"РћС€РёР±РєР° РїСЂРё РѕР±СЂР°Р±РѕС‚РєРµ {url}: {e}")
            return {'emails': []}

    def run(self):
        """Основная функция поиска."""
        try:
            all_results = []
            with sync_playwright() as p:
                if not self.is_running:
                    return

                self.emit_progress("Запуск браузера...")
                context = p.chromium.launch_persistent_context(
                    user_data_dir=self.profile_dir,
                    headless=False,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--no-first-run',
                        '--no-default-browser-check',
                        '--start-maximized',
                    ],
                    locale='ru-RU',
                    no_viewport=True,
                )
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined,
                    });
                """)

                page = context.pages[0] if context.pages else context.new_page()
                contacts_page = context.new_page() if self.collect_contacts else None

                page_number = self.page_from
                start_value = max(0, (self.page_from - 1) * 10)
                first_url = f"https://www.google.com/search?q={self.query}&hl=ru&start={start_value}&filter=0"
                page.goto(first_url, wait_until='domcontentloaded', timeout=45000)

                while self.is_running:
                    if self.is_captcha_page(page):
                        if not self.wait_for_captcha_resolution(page_number):
                            break
                        page.wait_for_load_state('domcontentloaded', timeout=45000)
                        continue

                    target_page = "ALL" if self.parse_all_pages else str(self.page_to)
                    self.emit_progress(f"Обработка страницы {page_number} из {target_page}...")
                    time.sleep(random.uniform(2, 4))

                    html = page.content()
                    soup = BeautifulSoup(html, 'html.parser')

                    result_blocks = (
                        soup.select('div.MjjYud') or
                        soup.select('div.g') or
                        soup.select('div[data-ved]') or
                        soup.select('.tF2Cxc') or
                        soup.select('div.ZINbbc') or
                        soup.select('div.kCrYT')
                    )
                    self.emit_progress(f"Найдено блоков на странице {page_number}: {len(result_blocks)}")

                    if not result_blocks:
                        self.emit_progress("Блоки результатов не найдены")
                        if page_number == self.page_from:
                            self.emit_progress("Возможно, Google блокирует запросы")
                        break

                    page_results = []
                    if self.results_per_page:
                        result_blocks = result_blocks[:self.results_per_page]

                    for i, block in enumerate(result_blocks):
                        if not self.is_running:
                            break
                        try:
                            title = ''
                            url_link = ''
                            cite = ''
                            snippet = ''

                            a_tag = (
                                block.select_one('a[href^="http"]') or
                                block.select_one('a[href^="https"]') or
                                block.select_one('a.zReHs') or
                                block.select_one('h3 a') or
                                block.select_one('a[data-ved]')
                            )
                            h3_tag = (
                                block.select_one('h3') or
                                block.select_one('h3.LC20lb') or
                                block.select_one('.DKV0Md') or
                                block.select_one('h3.r') or
                                block.select_one('[role="heading"]')
                            )
                            cite_tag = (
                                block.select_one('cite') or
                                block.select_one('cite.qLRx3b') or
                                block.select_one('.tjvcx') or
                                block.select_one('.UdvAnf')
                            )
                            snippet_tag = (
                                block.select_one('div.VwiC3b') or
                                block.select_one('.s') or
                                block.select_one('span[data-ved]') or
                                block.select_one('.st') or
                                block.select_one('.X5LH0c')
                            )

                            if a_tag:
                                url_link = a_tag.get('href', '')
                            if h3_tag:
                                title = h3_tag.get_text(strip=True)
                            if cite_tag:
                                cite = cite_tag.get_text(strip=True)
                            if snippet_tag:
                                snippet = snippet_tag.get_text(strip=True)

                            if url_link and not url_link.startswith('http'):
                                continue

                            if title and url_link:
                                result_data = {
                                    'title': title,
                                    'url': url_link,
                                    'cite': cite,
                                    'snippet': snippet
                                }
                                if self.collect_contacts and contacts_page is not None:
                                    self.emit_progress(f"Собираем контакты с: {url_link}")
                                    contacts = self.fetch_page_contacts(url_link, contacts_page)
                                    result_data.update({
                                        'emails': ', '.join(contacts.get('emails', []))
                                    })
                                page_results.append(result_data)
                        except Exception as e:
                            self.emit_progress(f"Ошибка при обработке блока {i}: {e}")
                            continue

                    if not page_results:
                        self.emit_progress(f"Нет результатов на странице {page_number}, завершаем сбор")
                        break

                    all_results.extend(page_results)
                    self.emit_progress(f"Собрано {len(page_results)} результатов со страницы {page_number}")

                    if not self.parse_all_pages and page_number >= self.page_to:
                        break

                    next_btn = page.locator('a#pnnext')
                    if next_btn.count() == 0:
                        self.emit_progress("Следующая страница недоступна. Завершаем сбор.")
                        break

                    try:
                        next_btn.first.click(timeout=15000)
                        page.wait_for_load_state('domcontentloaded', timeout=45000)
                    except Exception as e:
                        self.emit_progress(f"Не удалось перейти на следующую страницу: {e}")
                        break

                    page_number += 1
                    time.sleep(random.uniform(2, 4))

                context.close()

            df = pd.DataFrame(all_results)
            if not df.empty:
                df = df.drop_duplicates(subset=['url'], keep='first')
            self.results_ready.emit(df)

        except Exception as e:
            self.error_occurred.emit(f"Критическая ошибка: {str(e)}\n{traceback.format_exc()}")
class WhoisWorker(QThread):
    """Р¤РѕРЅРѕРІС‹Р№ РїРѕС‚РѕРє РґР»СЏ РїСЂРѕРІРµСЂРєРё РґРѕРјРµРЅРѕРІ С‡РµСЂРµР· WHOIS.ru"""
    progress_updated = pyqtSignal(str)
    whois_ready = pyqtSignal(object)
    error_occurred = pyqtSignal(str)

    def __init__(self, results_df: pd.DataFrame):
        super().__init__()
        self.results_df = results_df
        self.is_running = True

    def stop(self):
        self.is_running = False

    def emit_progress(self, message: str):
        if self.is_running:
            self.progress_updated.emit(message)

    def run(self):
        try:
            if self.results_df is None or self.results_df.empty:
                self.emit_progress("[WHOIS] РќРµС‚ РґР°РЅРЅС‹С… РґР»СЏ РѕР±СЂР°Р±РѕС‚РєРё")
                self.whois_ready.emit(self.results_df if self.results_df is not None else pd.DataFrame())
                return

            # РЎР±РѕСЂ СѓРЅРёРєР°Р»СЊРЅС‹С… РґРѕРјРµРЅРѕРІ
            unique_domains = set()
            for _, row in self.results_df.iterrows():
                if not self.is_running:
                    break
                domain = extract_domain_from_url(row.get('cite')) if 'cite' in row else None
                if not domain:
                    domain = extract_domain_from_url(row.get('url'))
                if domain:
                    unique_domains.add(domain)

            unique_domains = list(unique_domains)
            self.emit_progress(f"\n[WHOIS] РќР°Р№РґРµРЅРѕ СѓРЅРёРєР°Р»СЊРЅС‹С… РґРѕРјРµРЅРѕРІ РґР»СЏ РїСЂРѕРІРµСЂРєРё: {len(unique_domains)}")

            if not unique_domains:
                self.emit_progress("[WHOIS] РќРµС‚ РґРѕРјРµРЅРѕРІ РґР»СЏ РїСЂРѕРІРµСЂРєРё")
                self.whois_ready.emit(self.results_df)
                return

            # РџРѕР»СѓС‡РµРЅРёРµ РґР°РЅРЅС‹С… WHOIS
            whois_results: Dict[str, Dict[str, Optional[str]]] = {}
            for i, domain in enumerate(unique_domains, 1):
                if not self.is_running:
                    break
                self.emit_progress(f"[WHOIS] РћР±СЂР°Р±Р°С‚С‹РІР°СЋ РґРѕРјРµРЅ {i}/{len(unique_domains)}: {domain}")
                data = get_whois_data(domain)
                whois_results[domain] = data
                if data.get('whois_error'):
                    self.emit_progress(f"[WHOIS] РћС€РёР±РєР° РґР»СЏ {domain}: {data['whois_error']}")
                else:
                    self.emit_progress(f"[WHOIS] РЈСЃРїРµС€РЅРѕ РїРѕР»СѓС‡РµРЅС‹ РґР°РЅРЅС‹Рµ РґР»СЏ {domain}")

            # РћР±РѕРіР°С‰РµРЅРёРµ РёСЃС…РѕРґРЅРѕРіРѕ DataFrame
            enriched_rows: List[Dict] = []
            for _, row in self.results_df.iterrows():
                item = row.to_dict()
                domain = extract_domain_from_url(item.get('cite')) if item.get('cite') else None
                if not domain:
                    domain = extract_domain_from_url(item.get('url'))

                if domain and domain in whois_results:
                    info = whois_results[domain]
                    item.update({
                        'whois_domain': info.get('domain'),
                        'whois_citation_index': info.get('citation_index'),
                        'whois_alexa_rating': info.get('alexa_rating'),
                        'whois_registrar': info.get('registrar'),
                        'whois_registration_date': info.get('registration_date'),
                        'whois_expiration_date': info.get('expiration_date'),
                        'whois_days_until_expiration': info.get('days_until_expiration'),
                        'whois_check_date': info.get('check_date'),
                        'whois_external_links': info.get('external_links'),
                        'whois_internal_links': info.get('internal_links'),
                        'whois_total_anchors': info.get('total_anchors'),
                        'whois_outgoing_anchors': info.get('outgoing_anchors'),
                        'whois_domain_links': info.get('domain_links'),
                        'whois_page_title': info.get('page_title'),
                        'whois_page_description': info.get('page_description'),
                        'whois_error': info.get('whois_error')
                    })
                else:
                    item.update({
                        'whois_domain': None,
                        'whois_citation_index': None,
                        'whois_alexa_rating': None,
                        'whois_registrar': None,
                        'whois_registration_date': None,
                        'whois_expiration_date': None,
                        'whois_days_until_expiration': None,
                        'whois_check_date': None,
                        'whois_external_links': None,
                        'whois_internal_links': None,
                        'whois_total_anchors': None,
                        'whois_outgoing_anchors': None,
                        'whois_domain_links': None,
                        'whois_page_title': None,
                        'whois_page_description': None,
                        'whois_error': 'No domain found'
                    })
                enriched_rows.append(item)

            df_enriched = pd.DataFrame(enriched_rows)

            # РЎС‚Р°С‚РёСЃС‚РёРєР°
            successful = len([1 for _, r in df_enriched.iterrows() if r.get('whois_domain') and not r.get('whois_error')])
            failed = len([1 for _, r in df_enriched.iterrows() if r.get('whois_error') and r.get('whois_error') != 'No domain found'])
            no_domain = len([1 for _, r in df_enriched.iterrows() if r.get('whois_error') == 'No domain found'])

            self.emit_progress(f"[WHOIS] РЈСЃРїРµС€РЅРѕ РѕР±СЂР°Р±РѕС‚Р°РЅРѕ РґРѕРјРµРЅРѕРІ: {successful}")
            self.emit_progress(f"[WHOIS] РћС€РёР±РѕРє РїСЂРё РѕР±СЂР°Р±РѕС‚РєРµ: {failed}")
            self.emit_progress(f"[WHOIS] Р РµР·СѓР»СЊС‚Р°С‚РѕРІ Р±РµР· РґРѕРјРµРЅРѕРІ: {no_domain}")

            self.whois_ready.emit(df_enriched)

        except Exception as e:
            self.error_occurred.emit(f"[WHOIS] РљСЂРёС‚РёС‡РµСЃРєР°СЏ РѕС€РёР±РєР°: {str(e)}\n{traceback.format_exc()}")

class GoogleSearchGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.results_df = None
        self.whois_worker = None
        self.whois_checkbox = None
        self.report_button = None  # РљРЅРѕРїРєР° РґР»СЏ РіРµРЅРµСЂР°С†РёРё РѕС‚С‡РµС‚Р°
        self.parse_button = None
        self.resume_button = None
        self.all_pages_checkbox = None
        self.page_from_spinbox = None
        self.page_to_spinbox = None
        self.manual_session = ManualGoogleSession(base_dir)
        self.init_ui()

    def init_ui(self):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РїРѕР»СЊР·РѕРІР°С‚РµР»СЊСЃРєРѕРіРѕ РёРЅС‚РµСЂС„РµР№СЃР°"""
        self.setWindowTitle("Google Search Tool v1.1")
        self.setGeometry(100, 100, 800, 650)

        # РћСЃРЅРѕРІРЅРѕР№ РІРёРґР¶РµС‚
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # РћСЃРЅРѕРІРЅРѕР№ layout
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Р“СЂСѓРїРїР° РЅР°СЃС‚СЂРѕРµРє РїРѕРёСЃРєР°
        search_group = QGroupBox("РќР°СЃС‚СЂРѕР№РєРё РїРѕРёСЃРєР°")
        search_layout = QGridLayout()

        # РџРѕРёСЃРєРѕРІС‹Р№ Р·Р°РїСЂРѕСЃ
        search_layout.addWidget(QLabel("РџРѕРёСЃРєРѕРІС‹Р№ Р·Р°РїСЂРѕСЃ:"), 0, 0)
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Р’РІРµРґРёС‚Рµ РїРѕРёСЃРєРѕРІС‹Р№ Р·Р°РїСЂРѕСЃ...")
        search_layout.addWidget(self.query_input, 0, 1, 1, 2)

        # РЎС‚СЂР°РЅРёС†С‹ (РѕС‚/РґРѕ) РёР»Рё РІСЃРµ
        search_layout.addWidget(QLabel("РЎС‚СЂР°РЅРёС†С‹ (РѕС‚/РґРѕ):"), 1, 0)
        self.page_from_spinbox = QSpinBox()
        self.page_from_spinbox.setRange(1, 500)
        self.page_from_spinbox.setValue(1)
        search_layout.addWidget(self.page_from_spinbox, 1, 1)

        self.page_to_spinbox = QSpinBox()
        self.page_to_spinbox.setRange(1, 500)
        self.page_to_spinbox.setValue(3)
        search_layout.addWidget(self.page_to_spinbox, 1, 2)

        self.all_pages_checkbox = QCheckBox("РџР°СЂСЃРёС‚СЊ РІСЃРµ СЃС‚СЂР°РЅРёС†С‹ (РїРѕРєР° РµСЃС‚СЊ 'РЎР»РµРґСѓСЋС‰Р°СЏ')")
        search_layout.addWidget(self.all_pages_checkbox, 2, 0, 1, 3)

        # РћРіСЂР°РЅРёС‡РµРЅРёРµ СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ
        self.limit_results_checkbox = QCheckBox("РћРіСЂР°РЅРёС‡РёС‚СЊ СЂРµР·СѓР»СЊС‚Р°С‚С‹ РЅР° СЃС‚СЂР°РЅРёС†Рµ")
        search_layout.addWidget(self.limit_results_checkbox, 3, 0)
        self.results_per_page_spinbox = QSpinBox()
        self.results_per_page_spinbox.setRange(10, 100)
        self.results_per_page_spinbox.setValue(10)
        self.results_per_page_spinbox.setEnabled(False)
        search_layout.addWidget(self.results_per_page_spinbox, 3, 1)

        # РЎР±РѕСЂ РєРѕРЅС‚Р°РєС‚РѕРІ
        self.collect_contacts_checkbox = QCheckBox("РЎРѕР±РёСЂР°С‚СЊ email РєРѕРЅС‚Р°РєС‚С‹")
        search_layout.addWidget(self.collect_contacts_checkbox, 4, 0)

        # РџСЂРµРґР»Р°РіР°С‚СЊ WHOIS РїСЂРѕРІРµСЂРєСѓ
        self.whois_checkbox = QCheckBox("РџСЂРµРґР»Р°РіР°С‚СЊ РїСЂРѕРІРµСЂРєСѓ РґРѕРјРµРЅРѕРІ С‡РµСЂРµР· WHOIS.ru РїРѕСЃР»Рµ СЃР±РѕСЂР°")
        self.whois_checkbox.setChecked(True)
        search_layout.addWidget(self.whois_checkbox, 5, 0, 1, 2)

        search_group.setLayout(search_layout)
        main_layout.addWidget(search_group)

        # Р“СЂСѓРїРїР° Readme
        info_group = QGroupBox("РљР»СЋС‡РµРІС‹Рµ РѕСЃРѕР±РµРЅРЅРѕСЃС‚Рё Рё СЂРµРєРѕРјРµРЅРґР°С†РёРё")
        info_layout = QVBoxLayout()
        readme_text = ("<ul style='margin-left: -20px;'>"
                       "<li><b>РџСЂРѕРёР·РІРѕРґРёС‚РµР»СЊРЅРѕСЃС‚СЊ СЃР±РѕСЂР°:</b> РџСЂРёР»РѕР¶РµРЅРёРµ РѕР±СЂР°Р±Р°С‚С‹РІР°РµС‚ РґРѕ 100 СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ СЃ РєР°Р¶РґРѕР№ СЃС‚СЂР°РЅРёС†С‹ РїРѕРёСЃРєРѕРІРѕР№ РІС‹РґР°С‡Рё Google.</li>"
                       "<li><b>РћРіСЂР°РЅРёС‡РµРЅРёСЏ Google:</b> РџРѕРёСЃРєРѕРІР°СЏ СЃРёСЃС‚РµРјР° Google, РєР°Рє РїСЂР°РІРёР»Рѕ, РѕРіСЂР°РЅРёС‡РёРІР°РµС‚ РѕР±С‰РµРµ РєРѕР»РёС‡РµСЃС‚РІРѕ СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ РїСЂРёРјРµСЂРЅРѕ РґРѕ 300 РїРѕР·РёС†РёР№ (СЌРєРІРёРІР°Р»РµРЅС‚РЅРѕ 3 СЃС‚СЂР°РЅРёС†Р°Рј).</li>"
                       "<li><b>РЎР±РѕСЂ РєРѕРЅС‚Р°РєС‚РЅС‹С… РґР°РЅРЅС‹С…:</b> РђРєС‚РёРІР°С†РёСЏ С„СѓРЅРєС†РёРё СЃР±РѕСЂР° email-Р°РґСЂРµСЃРѕРІ Р·РЅР°С‡РёС‚РµР»СЊРЅРѕ СѓРІРµР»РёС‡РёРІР°РµС‚ РѕР±С‰РµРµ РІСЂРµРјСЏ РІС‹РїРѕР»РЅРµРЅРёСЏ Р·Р°РґР°С‡Рё, С‚Р°Рє РєР°Рє С‚СЂРµР±СѓРµС‚ РїРѕСЃР»РµРґРѕРІР°С‚РµР»СЊРЅРѕРіРѕ РїРѕСЃРµС‰РµРЅРёСЏ Рё Р°РЅР°Р»РёР·Р° РєР°Р¶РґРѕРіРѕ РЅР°Р№РґРµРЅРЅРѕРіРѕ РІРµР±-СЃР°Р№С‚Р°.</li>"
                       "</ul>")
        info_label = QLabel(readme_text)
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        info_group.setLayout(info_layout)
        main_layout.addWidget(info_group)

        # РљРЅРѕРїРєРё СѓРїСЂР°РІР»РµРЅРёСЏ
        buttons_layout = QHBoxLayout()
        self.search_button = QPushButton("РќР°С‡Р°С‚СЊ РїРѕРёСЃРє")
        self.search_button.clicked.connect(self.start_manual_search)
        buttons_layout.addWidget(self.search_button)

        self.parse_button = QPushButton("РќР°С‡Р°С‚СЊ РїР°СЂСЃРёРЅРі")
        self.parse_button.clicked.connect(self.start_search)
        self.parse_button.setEnabled(False)
        buttons_layout.addWidget(self.parse_button)

        self.resume_button = QPushButton("РџСЂРѕРґРѕР»Р¶РёС‚СЊ РїРѕСЃР»Рµ РєР°РїС‡Рё")
        self.resume_button.clicked.connect(self.resume_after_captcha)
        self.resume_button.setEnabled(False)
        buttons_layout.addWidget(self.resume_button)

        self.stop_button = QPushButton("РћСЃС‚Р°РЅРѕРІРёС‚СЊ")
        self.stop_button.clicked.connect(self.stop_search)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)

        self.save_button = QPushButton("РЎРѕС…СЂР°РЅРёС‚СЊ CSV/Excel")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        buttons_layout.addWidget(self.save_button)

        # РљРЅРѕРїРєР° РґР»СЏ РіРµРЅРµСЂР°С†РёРё HTML-РѕС‚С‡РµС‚Р°
        self.report_button = QPushButton("РЎРіРµРЅРµСЂРёСЂРѕРІР°С‚СЊ HTML-РѕС‚С‡РµС‚")
        self.report_button.clicked.connect(self.generate_html_report)
        self.report_button.setEnabled(False)
        buttons_layout.addWidget(self.report_button)

        main_layout.addLayout(buttons_layout)

        # РџСЂРѕРіСЂРµСЃСЃ Р±Р°СЂ
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # РўРµРєСЃС‚РѕРІРѕРµ РїРѕР»Рµ РґР»СЏ РІС‹РІРѕРґР°
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        main_layout.addWidget(self.output_text)

        # РљРЅРѕРїРєР° РґР»СЏ СЃРІСЏР·Рё
        feedback_layout = QHBoxLayout()
        self.feedback_button = QPushButton("РџСЂРµРґР»РѕР¶РёС‚СЊ СѓР»СѓС‡С€РµРЅРёРµ")
        self.feedback_button.setCursor(Qt.PointingHandCursor)
        self.feedback_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-weight: bold;
                border-radius: 5px;
                padding: 6px 12px;
                border: 1px solid #2980b9;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1f618d;
            }
        """)
        self.feedback_button.clicked.connect(self.open_feedback_link)
        feedback_layout.addStretch()
        feedback_layout.addWidget(self.feedback_button)
        main_layout.addLayout(feedback_layout)

        # РџРѕРґРєР»СЋС‡РµРЅРёРµ СЃРёРіРЅР°Р»РѕРІ
        self.limit_results_checkbox.toggled.connect(
            self.results_per_page_spinbox.setEnabled
        )
        self.all_pages_checkbox.toggled.connect(self.page_from_spinbox.setDisabled)
        self.all_pages_checkbox.toggled.connect(self.page_to_spinbox.setDisabled)

    def open_feedback_link(self):
        """РћС‚РєСЂС‹РІР°РµС‚ СЃСЃС‹Р»РєСѓ РґР»СЏ РѕР±СЂР°С‚РЅРѕР№ СЃРІСЏР·Рё РІ Telegram"""
        QDesktopServices.openUrl(QUrl("https://t.me/Userspoi"))

    def start_manual_search(self):
        """РћС‚РєСЂС‹РІР°РµС‚ РІРёРґРёРјС‹Р№ Р±СЂР°СѓР·РµСЂ РґР»СЏ СЂСѓС‡РЅРѕР№ РєР°РїС‡Рё Рё РїРѕРґРіРѕС‚РѕРІРєРё СЃРµСЃСЃРёРё."""
        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self, "РћС€РёР±РєР°", "Р’РІРµРґРёС‚Рµ РїРѕРёСЃРєРѕРІС‹Р№ Р·Р°РїСЂРѕСЃ!")
            return

        try:
            self.manual_session.start_search(query)
            self.parse_button.setEnabled(True)
            self.resume_button.setEnabled(False)
            self.output_text.append("РћС‚РєСЂС‹С‚ Р±СЂР°СѓР·РµСЂ СЃ РїРѕРёСЃРєРѕРІС‹Рј Р·Р°РїСЂРѕСЃРѕРј.")
            self.output_text.append("Р•СЃР»Рё РµСЃС‚СЊ РєР°РїС‡Р° - СЂРµС€РёС‚Рµ РµРµ РІ Р±СЂР°СѓР·РµСЂРµ.")
            self.output_text.append("РџРѕСЃР»Рµ РїРѕСЏРІР»РµРЅРёСЏ СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ РЅР°Р¶РјРёС‚Рµ 'РќР°С‡Р°С‚СЊ РїР°СЂСЃРёРЅРі'.")
        except Exception as e:
            QMessageBox.critical(self, "РћС€РёР±РєР°", f"РќРµ СѓРґР°Р»РѕСЃСЊ РѕС‚РєСЂС‹С‚СЊ Р±СЂР°СѓР·РµСЂ: {e}")

    def resume_after_captcha(self):
        if self.worker:
            self.worker.resume_after_captcha()
            self.resume_button.setEnabled(False)
            self.output_text.append("РџСЂРѕРґРѕР»Р¶РµРЅРёРµ РїРѕСЃР»Рµ РєР°РїС‡Рё Р·Р°РїСЂРѕС€РµРЅРѕ.")

    def start_search(self):
        """Р—Р°РїСѓСЃРє РїРѕРёСЃРєР°"""
        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self, "РћС€РёР±РєР°", "Р’РІРµРґРёС‚Рµ РїРѕРёСЃРєРѕРІС‹Р№ Р·Р°РїСЂРѕСЃ!")
            return
        if not self.manual_session.is_active():
            QMessageBox.warning(self, "РџРѕРёСЃРє", "РЎРЅР°С‡Р°Р»Р° РЅР°Р¶РјРёС‚Рµ 'РќР°С‡Р°С‚СЊ РїРѕРёСЃРє' Рё СЂРµС€РёС‚Рµ РєР°РїС‡Сѓ РІ Р±СЂР°СѓР·РµСЂРµ.")
            return
        profile_dir = self.manual_session.profile_dir
        self.manual_session.stop()

        page_from = self.page_from_spinbox.value()
        page_to = self.page_to_spinbox.value()
        parse_all_pages = self.all_pages_checkbox.isChecked()
        if not parse_all_pages and page_to < page_from:
            QMessageBox.warning(self, "РћС€РёР±РєР°", "РџРѕР»Рµ 'РґРѕ' РЅРµ РјРѕР¶РµС‚ Р±С‹С‚СЊ РјРµРЅСЊС€Рµ РїРѕР»СЏ 'РѕС‚'.")
            return

        collect_contacts = self.collect_contacts_checkbox.isChecked()
        results_per_page = None
        if self.limit_results_checkbox.isChecked():
            results_per_page = self.results_per_page_spinbox.value()

        # РћС‡РёСЃС‚РєР° РІС‹РІРѕРґР°
        self.output_text.clear()
        self.output_text.append(f"РќР°С‡РёРЅР°РµРј РїРѕРёСЃРє РїРѕ Р·Р°РїСЂРѕСЃСѓ: '{query}'")
        if parse_all_pages:
            self.output_text.append("РЎС‚СЂР°РЅРёС†С‹: РІСЃРµ РґРѕСЃС‚СѓРїРЅС‹Рµ")
        else:
            self.output_text.append(f"Р”РёР°РїР°Р·РѕРЅ СЃС‚СЂР°РЅРёС†: {page_from}-{page_to}")
        if results_per_page:
            self.output_text.append(f"Р РµР·СѓР»СЊС‚Р°С‚РѕРІ РЅР° СЃС‚СЂР°РЅРёС†Рµ: {results_per_page}")
        if collect_contacts:
            self.output_text.append("РЎР±РѕСЂ РєРѕРЅС‚Р°РєС‚РѕРІ: РІРєР»СЋС‡РµРЅ")
        self.output_text.append("-" * 50)

        # РЎР±СЂРѕСЃ WHOIS
        self.whois_worker = None

        # РќР°СЃС‚СЂРѕР№РєР° UI РґР»СЏ РїРѕРёСЃРєР°
        self.search_button.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.report_button.setEnabled(False)  # РћС‚РєР»СЋС‡Р°РµРј РєРЅРѕРїРєСѓ РѕС‚С‡РµС‚Р°
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # РќРµРѕРїСЂРµРґРµР»РµРЅРЅС‹Р№ РїСЂРѕРіСЂРµСЃСЃ

        # РЎРѕР·РґР°РЅРёРµ Рё Р·Р°РїСѓСЃРє worker'Р°
        self.worker = GoogleSearchWorker(
            query,
            page_from,
            page_to,
            parse_all_pages,
            collect_contacts,
            results_per_page,
            profile_dir,
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.captcha_detected.connect(self.on_captcha_detected)
        self.worker.results_ready.connect(self.on_results_ready)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.finished.connect(self.on_search_finished)
        self.worker.start()

    def stop_search(self):
        """РћСЃС‚Р°РЅРѕРІРєР° РїРѕРёСЃРєР°"""
        self.resume_button.setEnabled(False)
        if self.worker:
            self.worker.stop()
            self.worker.quit()
            self.worker.wait()
            self.output_text.append("РџРѕРёСЃРє РѕСЃС‚Р°РЅРѕРІР»РµРЅ РїРѕР»СЊР·РѕРІР°С‚РµР»РµРј")

        if self.whois_worker:
            self.whois_worker.stop()
            self.whois_worker.quit()
            self.whois_worker.wait()
            self.output_text.append("WHOIS-РїСЂРѕРІРµСЂРєР° РѕСЃС‚Р°РЅРѕРІР»РµРЅР° РїРѕР»СЊР·РѕРІР°С‚РµР»РµРј")

    def update_progress(self, message):
        """РћР±РЅРѕРІР»РµРЅРёРµ РїСЂРѕРіСЂРµСЃСЃР°"""
        self.output_text.append(message)
        self.output_text.moveCursor(self.output_text.textCursor().End)

    def on_captcha_detected(self, page_number):
        self.resume_button.setEnabled(True)
        self.output_text.append(
            f"РљР°РїС‡Р° РЅР° СЃС‚СЂР°РЅРёС†Рµ {page_number}: "
            f"СЂРµС€РёС‚Рµ РµРµ РІ Р±СЂР°СѓР·РµСЂРµ Рё РЅР°Р¶РјРёС‚Рµ 'РџСЂРѕРґРѕР»Р¶РёС‚СЊ РїРѕСЃР»Рµ РєР°РїС‡Рё'."
        )

    def on_results_ready(self, df):
        """РћР±СЂР°Р±РѕС‚РєР° РіРѕС‚РѕРІС‹С… СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ"""
        self.results_df = df
        if not df.empty:
            self.output_text.append(f"\nРџРѕРёСЃРє Р·Р°РІРµСЂС€РµРЅ! РќР°Р№РґРµРЅРѕ {len(df)} СѓРЅРёРєР°Р»СЊРЅС‹С… СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ")
            if self.collect_contacts_checkbox.isChecked():
                total_emails = sum(1 for _, row in df.iterrows() if row.get('emails'))
                self.output_text.append(f"РќР°Р№РґРµРЅРѕ СЃР°Р№С‚РѕРІ СЃ email: {total_emails}")
                # РџРѕРєР°Р·С‹РІР°РµРј РїСЂРёРјРµСЂС‹ РЅР°Р№РґРµРЅРЅС‹С… РєРѕРЅС‚Р°РєС‚РѕРІ
                if total_emails > 0:
                    self.output_text.append("\nРџСЂРёРјРµСЂС‹ РЅР°Р№РґРµРЅРЅС‹С… email:")
                    count = 0
                    for _, row in df.iterrows():
                        if row.get('emails') and count < 3:
                            self.output_text.append(f"  {row['url']}: {row['emails'][:100]}...")
                            count += 1
            self.save_button.setEnabled(True)
            self.report_button.setEnabled(True)  # РђРєС‚РёРІРёСЂСѓРµРј РєРЅРѕРїРєСѓ РѕС‚С‡РµС‚Р°
        else:
            self.output_text.append("Р РµР·СѓР»СЊС‚Р°С‚С‹ РЅРµ РЅР°Р№РґРµРЅС‹")

        # РџСЂРµРґР»РѕР¶РµРЅРёРµ WHOIS РїСЂРѕРІРµСЂРєРё РєР°Рє РІ Yandex-СЃРєСЂРёРїС‚Рµ
        if self.results_df is not None and not self.results_df.empty and self.whois_checkbox.isChecked():
            self.output_text.append("\n" + "=" * 60)
            self.output_text.append("РћРЎРќРћР’РќРћР™ РџРђР РЎРРќР“ Р—РђР’Р•Р РЁР•Рќ")
            self.output_text.append("=" * 60)
            reply = QMessageBox.question(
                self,
                "WHOIS",
                "РҐРѕС‚РёС‚Рµ РїСЂРѕРІРµСЂРёС‚СЊ РґРѕРјРµРЅС‹ С‡РµСЂРµР· WHOIS.ru?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self.output_text.append("\n[WHOIS] РќР°С‡РёРЅР°СЋ РїСЂРѕРІРµСЂРєСѓ РґРѕРјРµРЅРѕРІ...")
                self.start_whois_check()
            else:
                self.output_text.append("[WHOIS] РџСЂРѕРІРµСЂРєР° РґРѕРјРµРЅРѕРІ РїСЂРѕРїСѓС‰РµРЅР°.")

    def start_whois_check(self):
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "WHOIS", "РќРµС‚ РґР°РЅРЅС‹С… РґР»СЏ WHOIS-РїСЂРѕРІРµСЂРєРё")
            return

        # РќР°СЃС‚СЂРѕР№РєР° UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.search_button.setEnabled(False)
        self.parse_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.report_button.setEnabled(False)  # РћС‚РєР»СЋС‡Р°РµРј РЅР° РІСЂРµРјСЏ WHOIS

        # Р—Р°РїСѓСЃРє WhoisWorker
        self.whois_worker = WhoisWorker(self.results_df)
        self.whois_worker.progress_updated.connect(self.update_progress)
        self.whois_worker.whois_ready.connect(self.on_whois_ready)
        self.whois_worker.error_occurred.connect(self.on_error)
        self.whois_worker.finished.connect(self.on_whois_finished)
        self.whois_worker.start()

    def on_whois_ready(self, df_enriched: pd.DataFrame):
        # РћР±РЅРѕРІР»СЏРµРј С‚РµРєСѓС‰РёР№ DataFrame РЅР° РѕР±РѕРіР°С‰С‘РЅРЅС‹Р№
        self.results_df = df_enriched
        self.output_text.append("\n[WHOIS] РћР±РѕРіР°С‰РµРЅРЅС‹Рµ РґР°РЅРЅС‹Рµ РїРѕР»СѓС‡РµРЅС‹. РњРѕР¶РµС‚Рµ СЃРѕС…СЂР°РЅРёС‚СЊ СЂРµР·СѓР»СЊС‚Р°С‚С‹.")
        self.save_button.setEnabled(True)
        self.report_button.setEnabled(True)  # РђРєС‚РёРІРёСЂСѓРµРј РєРЅРѕРїРєСѓ РѕС‚С‡РµС‚Р° РїРѕСЃР»Рµ WHOIS

    def on_whois_finished(self):
        self.progress_bar.setVisible(False)
        self.search_button.setEnabled(True)
        self.parse_button.setEnabled(self.manual_session.is_active())
        self.resume_button.setEnabled(False)

    def on_error(self, error_message):
        """РћР±СЂР°Р±РѕС‚РєР° РѕС€РёР±РѕРє"""
        self.output_text.append(f"РћРЁРР‘РљРђ: {error_message}")
        QMessageBox.critical(self, "РћС€РёР±РєР°", error_message)

    def on_search_finished(self):
        """Р—Р°РІРµСЂС€РµРЅРёРµ РїРѕРёСЃРєР°"""
        self.search_button.setEnabled(True)
        self.parse_button.setEnabled(self.manual_session.is_active())
        self.resume_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        # Р•СЃР»Рё WHOIS СѓР¶Рµ Р·Р°РїСѓС‰РµРЅ вЂ” UI РѕСЃС‚Р°РЅРµС‚СЃСЏ РІ РЅРµРѕРїСЂРµРґРµР»С‘РЅРЅРѕРј РїСЂРѕРіСЂРµСЃСЃРµ, РЅРµ РјРµРЅСЏРµРј

    def closeEvent(self, event):
        """Р“Р°СЂР°РЅС‚РёСЂРѕРІР°РЅРЅРѕ Р·Р°РєСЂС‹РІР°РµС‚ СЂСѓС‡РЅСѓСЋ СЃРµСЃСЃРёСЋ Р±СЂР°СѓР·РµСЂР°."""
        try:
            self.manual_session.stop()
        finally:
            super().closeEvent(event)

    def save_results(self):
        """РЎРѕС…СЂР°РЅРµРЅРёРµ СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ"""
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "РћС€РёР±РєР°", "РќРµС‚ РґР°РЅРЅС‹С… РґР»СЏ СЃРѕС…СЂР°РЅРµРЅРёСЏ!")
            return

        query = self.query_input.text().strip()
        default_filename = f"google_results_{query.replace(' ', '_')}.csv"
        dialog = QFileDialog(self, "РЎРѕС…СЂР°РЅРёС‚СЊ СЂРµР·СѓР»СЊС‚Р°С‚С‹")
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setNameFilter("CSV files (*.csv);;Excel files (*.xlsx);;All files (*.*)")
        dialog.selectFile(default_filename)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)

        filename = ""
        if dialog.exec_():
            selected = dialog.selectedFiles()
            if selected:
                filename = selected[0]

        if filename:
            try:
                if filename.endswith('.xlsx'):
                    self.results_df.to_excel(filename, index=False)
                else:
                    self.results_df.to_csv(filename, index=False, encoding="utf-8-sig")
                self.output_text.append(f"Р РµР·СѓР»СЊС‚Р°С‚С‹ СЃРѕС…СЂР°РЅРµРЅС‹ РІ: {filename}")
                QMessageBox.information(self, "РЈСЃРїРµС…", f"Р РµР·СѓР»СЊС‚Р°С‚С‹ СЃРѕС…СЂР°РЅРµРЅС‹ РІ:\n{filename}")
            except Exception as e:
                error_msg = f"РћС€РёР±РєР° РїСЂРё СЃРѕС…СЂР°РЅРµРЅРёРё: {str(e)}"
                self.output_text.append(error_msg)
                QMessageBox.critical(self, "РћС€РёР±РєР°", error_msg)

    def generate_html_report(self):
        """Р“РµРЅРµСЂРёСЂСѓРµС‚ РёРЅС‚РµСЂР°РєС‚РёРІРЅС‹Р№ HTML-РѕС‚С‡РµС‚ СЃ С„РёР»СЊС‚СЂР°РјРё Рё РєРЅРѕРїРєРѕР№ СЌРєСЃРїРѕСЂС‚Р°."""
        if self.results_df is None or self.results_df.empty:
            QMessageBox.warning(self, "РћС€РёР±РєР°", "РќРµС‚ РґР°РЅРЅС‹С… РґР»СЏ РіРµРЅРµСЂР°С†РёРё РѕС‚С‡РµС‚Р°!")
            return

        # РЎРѕР·РґР°РµРј РєРѕРїРёСЋ DataFrame, С‡С‚РѕР±С‹ РЅРµ РјРѕРґРёС„РёС†РёСЂРѕРІР°С‚СЊ РѕСЂРёРіРёРЅР°Р»
        df_report = self.results_df.copy()

        # РћС‡РёС‰Р°РµРј РёРјРµРЅР° СЃС‚РѕР»Р±С†РѕРІ РґР»СЏ HTML (СѓР±РёСЂР°РµРј С‚РѕС‡РєРё Рё РїСЂРѕР±РµР»С‹)
        df_report.columns = [col.replace('.', '_').replace(' ', '_') for col in df_report.columns]

        # Р“РµРЅРµСЂРёСЂСѓРµРј HTML-С‚Р°Р±Р»РёС†Сѓ СЃ РїРѕРјРѕС‰СЊСЋ pandas
        html_table = df_report.to_html(
            table_id='dataTable',
            classes='display compact cell-border stripe hover order-column',
            escape=False,
            index=False
        )

        # РЁР°Р±Р»РѕРЅ HTML СЃ РїРѕРґРєР»СЋС‡РµРЅРёРµРј DataTables Рё РєРЅРѕРїРєРѕР№ СЌРєСЃРїРѕСЂС‚Р° (Р±РµР· РєРЅРѕРїРєРё РїРµС‡Р°С‚Рё)
        html_template = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>РћС‚С‡РµС‚ РїРѕ РїРѕРёСЃРєСѓ: {self.query_input.text()}</title>

    <!-- DataTables CSS -->
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/dt/jq-3.7.0/jszip-3.10.1/dt-2.0.3/af-2.7.0/b-3.0.1/b-colvis-3.0.1/b-html5-3.0.1/b-print-3.0.1/cr-2.0.0/date-1.5.2/fc-5.0.0/fh-4.0.1/kt-2.12.1/r-3.0.1/rg-1.5.0/rr-1.5.0/sc-2.4.1/sb-1.7.0/sp-2.3.0/sl-2.0.0/sr-1.4.1/datatables.min.css"/>

    <!-- jQuery (РѕР±СЏР·Р°С‚РµР»РµРЅ РґР»СЏ DataTables) -->
    <script type="text/javascript" src="https://code.jquery.com/jquery-3.7.1.min.js"></script>

    <!-- DataTables JS -->
    <script type="text/javascript" src="https://cdn.datatables.net/v/dt/jq-3.7.0/jszip-3.10.1/dt-2.0.3/af-2.7.0/b-3.0.1/b-colvis-3.0.1/b-html5-3.0.1/b-print-3.0.1/cr-2.0.0/date-1.5.2/fc-5.0.0/fh-4.0.1/kt-2.12.1/r-3.0.1/rg-1.5.0/rr-1.5.0/sc-2.4.1/sb-1.7.0/sp-2.3.0/sl-2.0.0/sr-1.4.1/datatables.min.js"></script>

    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            text-align: center;
            margin-bottom: 20px;
        }}
        #exportButtons {{
            margin-bottom: 15px;
            text-align: center;
        }}
        .dt-buttons {{
            display: inline-block;
        }}
        .dt-button {{
            background-color: #007bff !important;
            color: white !important;
            border: none !important;
            padding: 8px 16px !important;
            margin: 5px !important;
            border-radius: 4px !important;
            cursor: pointer !important;
        }}
        .dt-button:hover {{
            background-color: #0056b3 !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>РћС‚С‡РµС‚ РїРѕ РїРѕРёСЃРєСѓ: {self.query_input.text()}</h1>

        <div id="exportButtons">
            <!-- РљРЅРѕРїРєРё СЌРєСЃРїРѕСЂС‚Р° Р±СѓРґСѓС‚ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅС‹ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё DataTables -->
        </div>

        {html_table}

    </div>

    <script>
        $(document).ready(function() {{
            $('#dataTable').DataTable({{
                "language": {{
                    "url": "https://cdn.datatables.net/plug-ins/2.0.3/i18n/ru.json"
                }},
                "pageLength": 25,
                "dom": 'Bfrtip',
                "buttons": [
                    {{
                        "extend": 'csvHtml5',
                        "text": 'РЎРєР°С‡Р°С‚СЊ CSV',
                        "className": 'dt-button',
                        "charset": 'utf-8',
                        "bom": true,
                        "filename": 'report_{self.query_input.text().replace(' ', '_')}'
                    }},
                    {{
                        "extend": 'excelHtml5',
                        "text": 'РЎРєР°С‡Р°С‚СЊ Excel',
                        "className": 'dt-button',
                        "filename": 'report_{self.query_input.text().replace(' ', '_')}'
                    }},
                    // РљРЅРѕРїРєР° РїРµС‡Р°С‚Рё СѓРґР°Р»РµРЅР° РїРѕ С‚СЂРµР±РѕРІР°РЅРёСЋ
                    {{
                        "extend": 'colvis',
                        "text": 'РџРѕРєР°Р·Р°С‚СЊ/РЎРєСЂС‹С‚СЊ СЃС‚РѕР»Р±С†С‹',
                        "className": 'dt-button'
                    }}
                ],
                "initComplete": function() {{
                    // Р”РѕР±Р°РІР»СЏРµРј С„РёР»СЊС‚СЂС‹ РїРѕРґ РєР°Р¶РґС‹Рј СЃС‚РѕР»Р±С†РѕРј
                    this.api().columns().every(function() {{
                        var column = this;
                        var header = $(column.header());
                        var title = header.text();
                        
                        // РЎРѕР·РґР°РµРј input РґР»СЏ С„РёР»СЊС‚СЂР°С†РёРё
                        var input = $('<input type="text" placeholder="Р¤РёР»СЊС‚СЂ ' + title + '" />')
                            .appendTo($(column.footer()).empty())
                            .on('keyup change clear', function() {{
                                if (column.search() !== this.value) {{
                                    column
                                        .search(this.value)
                                        .draw();
                                }}
                            }});
                    }});
                }}
            }});
        }});
    </script>
</body>
</html>
        """

        # РЎРѕС…СЂР°РЅСЏРµРј HTML-С„Р°Р№Р» РІРѕ РІСЂРµРјРµРЅРЅСѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ
        query = self.query_input.text().strip()
        temp_filename = f"interactive_report_{query.replace(' ', '_')}.html"
        temp_path = os.path.join(os.getcwd(), temp_filename)  # РЎРѕС…СЂР°РЅСЏРµРј РІ С‚РµРєСѓС‰РµР№ РґРёСЂРµРєС‚РѕСЂРёРё

        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(html_template)
            self.output_text.append(f"РРЅС‚РµСЂР°РєС‚РёРІРЅС‹Р№ HTML-РѕС‚С‡РµС‚ СЃРіРµРЅРµСЂРёСЂРѕРІР°РЅ: {temp_path}")

            # РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРё РѕС‚РєСЂС‹РІР°РµРј С„Р°Р№Р» РІ Р±СЂР°СѓР·РµСЂРµ
            QDesktopServices.openUrl(QUrl.fromLocalFile(temp_path))

            QMessageBox.information(self, "РЈСЃРїРµС…", f"РћС‚С‡РµС‚ РѕС‚РєСЂС‹С‚ РІ РІР°С€РµРј Р±СЂР°СѓР·РµСЂРµ!")

        except Exception as e:
            error_msg = f"РћС€РёР±РєР° РїСЂРё РіРµРЅРµСЂР°С†РёРё РёР»Рё РѕС‚РєСЂС‹С‚РёРё HTML-РѕС‚С‡РµС‚Р°: {str(e)}"
            self.output_text.append(error_msg)
            QMessageBox.critical(self, "РћС€РёР±РєР°", error_msg)

def main():
    app = QApplication(sys.argv)
    # РЈСЃС‚Р°РЅРѕРІРєР° СЃС‚РёР»СЏ РїСЂРёР»РѕР¶РµРЅРёСЏ
    app.setStyle('Fusion')
    # РЎРѕР·РґР°РЅРёРµ Рё РїРѕРєР°Р· РіР»Р°РІРЅРѕРіРѕ РѕРєРЅР°
    window = GoogleSearchGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

